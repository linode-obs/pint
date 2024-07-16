package checks

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/common/model"

	"github.com/cloudflare/pint/internal/discovery"
	"github.com/cloudflare/pint/internal/output"
	"github.com/cloudflare/pint/internal/parser"
	"github.com/cloudflare/pint/internal/promapi"
)

const (
	AlertsCheckName = "alerts/count"
)

func NewAlertsCheck(prom *promapi.FailoverGroup, lookBack, step, resolve time.Duration, minCount int, comment string, severity Severity, expandRecordingRules bool) AlertsCheck {
	return AlertsCheck{
		prom:                 prom,
		lookBack:             lookBack,
		step:                 step,
		resolve:              resolve,
		minCount:             minCount,
		comment:              comment,
		severity:             severity,
		expandRecordingRules: expandRecordingRules,
	}
}

type AlertsCheck struct {
	prom                 *promapi.FailoverGroup
	comment              string
	lookBack             time.Duration
	step                 time.Duration
	resolve              time.Duration
	minCount             int
	severity             Severity
	expandRecordingRules bool
}

func (c AlertsCheck) Meta() CheckMeta {
	return CheckMeta{
		States: []discovery.ChangeType{
			discovery.Noop,
			discovery.Added,
			discovery.Modified,
			discovery.Moved,
		},
		IsOnline: true,
	}
}

func (c AlertsCheck) String() string {
	return fmt.Sprintf("%s(%s)", AlertsCheckName, c.prom.Name())
}

func (c AlertsCheck) Reporter() string {
	return AlertsCheckName
}

func (c AlertsCheck) Check(ctx context.Context, _ discovery.Path, rule parser.Rule, entries []discovery.Entry) (problems []Problem) {
	if rule.AlertingRule == nil {
		return problems
	}

	if rule.AlertingRule.Expr.SyntaxError != nil {
		return problems
	}

	params := promapi.NewRelativeRange(c.lookBack, c.step)

	// We only want to expand recording rules if they don't exist in Prometheus yet, so we need to
	// check each selector to determine if it exists and, if not, if there's a recording rule we can expand to replace it.
	if c.expandRecordingRules {
		newQuery := rule.AlertingRule.Expr.Query.Expr.String()
		foundSeries := map[string]bool{}
		sc := NewSeriesCheck(c.prom)
		for _, selector := range getNonFallbackSelectors(rule.AlertingRule.Expr.Query) {
			if _, ok := foundSeries[selector.String()]; ok {
				continue
			}
			foundSeries[selector.String()] = false

			bareSelector := stripLabels(selector)

			slog.Debug("Checking if selector returns anything", slog.String("check", c.Reporter()), slog.String("selector", (&selector).String()))
			count, err := sc.instantSeriesCount(ctx, fmt.Sprintf("count(%s)", selector.String()))
			if err != nil {
				text, severity := textAndSeverityFromError(err, c.Reporter(), c.prom.Name(), Bug)
				prb := Problem{
					Lines:    rule.AlertingRule.Expr.Value.Lines,
					Reporter: c.Reporter(),
					Text:     text,
					Severity: severity,
				}
				problems = append(problems, prb)
				continue
			}
			if count > 0 {
				foundSeries[selector.String()] = true
				continue

			}

			// Check if we have a recording rule that provides this metric before we give up
			var rr *parser.RecordingRule
			for _, entry := range entries {
				if entry.Rule.RecordingRule != nil &&
					entry.Rule.Error.Err == nil &&
					entry.Rule.RecordingRule.Record.Value == bareSelector.String() {
					rr = entry.Rule.RecordingRule
					break
				}
			}
			if rr != nil {
				// Validate recording rule instead
				slog.Debug("Metric is provided by recording rule", slog.String("selector", selector.String()))
				expr := fmt.Sprintf("(%s)", rr.Expr.Value.Value)
				// If the recording rule adds labels to its resultant series, we can use label_replace to ensure they're available
				// for the rest of the alerting query to use.
				for _, lbl := range rr.Labels.Items {
					expr = fmt.Sprintf("label_replace(%s, \"%s\", \"%s\", \"\", \"\")", expr, lbl.Key.Value, lbl.Value.Value)
				}
				newQuery = strings.ReplaceAll(newQuery, selector.String(), fmt.Sprintf("(%s)", expr))
				slog.Debug("Query is now updated", slog.String("query", newQuery))
				foundSeries[selector.String()] = true
				continue
			}
		}
		for selector, found := range foundSeries {
			if !found {
				slog.Warn("Could not find a series (or recording rule replacement)", slog.String("selector", selector))
			}
		}

		rule.AlertingRule.Expr.Value.Value = newQuery
	}

	qr, err := c.prom.RangeQuery(ctx, rule.AlertingRule.Expr.Value.Value, params)
	if err != nil {
		text, severity := textAndSeverityFromError(err, c.Reporter(), c.prom.Name(), Bug)
		problems = append(problems, Problem{
			Lines:    rule.AlertingRule.Expr.Value.Lines,
			Reporter: c.Reporter(),
			Text:     text,
			Severity: severity,
		})
		return problems
	}

	if len(qr.Series.Ranges) > 0 {
		promUptime, err := c.prom.RangeQuery(ctx, fmt.Sprintf("count(%s)", c.prom.UptimeMetric()), params)
		if err != nil {
			slog.Warn("Cannot detect Prometheus uptime gaps", slog.Any("err", err), slog.String("name", c.prom.Name()))
		} else {
			// FIXME: gaps are not used
			qr.Series.FindGaps(promUptime.Series, qr.Series.From, qr.Series.Until)
		}
	}

	var forDur model.Duration
	if rule.AlertingRule.For != nil {
		forDur, _ = model.ParseDuration(rule.AlertingRule.For.Value)
	}
	var keepFiringForDur model.Duration
	if rule.AlertingRule.KeepFiringFor != nil {
		keepFiringForDur, _ = model.ParseDuration(rule.AlertingRule.KeepFiringFor.Value)
	}

	var alerts int
	for _, r := range qr.Series.Ranges {
		// If `keepFiringFor` is not defined its Duration will be 0
		if r.End.Sub(r.Start) > (time.Duration(forDur) + time.Duration(keepFiringForDur)) {
			alerts++
		}
	}

	if alerts < c.minCount {
		return problems
	}

	delta := qr.Series.Until.Sub(qr.Series.From).Round(time.Minute)
	details := fmt.Sprintf(`To get a preview of the alerts that would fire please [click here](%s/graph?g0.expr=%s&g0.tab=0&g0.range_input=%s).`,
		qr.URI, url.QueryEscape(rule.AlertingRule.Expr.Value.Value), output.HumanizeDuration(delta),
	)
	if c.comment != "" {
		details = fmt.Sprintf("%s\n%s", details, maybeComment(c.comment))
	}

	problems = append(problems, Problem{
		Lines:    rule.AlertingRule.Expr.Value.Lines,
		Reporter: c.Reporter(),
		Text:     fmt.Sprintf("%s would trigger %d alert(s) in the last %s.", promText(c.prom.Name(), qr.URI), alerts, output.HumanizeDuration(delta)),
		Details:  details,
		Severity: c.severity,
	})
	return problems
}
