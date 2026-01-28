import type { Express } from "express";
import {
  getInjectionScanMetrics,
  getInjectionScanConfig,
  resetInjectionScanMetrics,
} from "./pi-embedded-subscribe.tools.js";

/**
 * Attaches injection scan metrics routes to the Express app.
 *
 * GET /debug/injection-stats - Get current metrics with computed statistics
 * POST /debug/injection-stats/reset - Reset metrics (requires confirmation)
 */
export function attachInjectionScanRoutes(app: Express): void {
  // Get injection scan metrics
  app.get("/debug/injection-stats", (_req, res) => {
    try {
      const metrics = getInjectionScanMetrics();
      const config = getInjectionScanConfig();

      res.json({
        ok: true,
        config: {
          enabled: config.enabled,
          minSeverity: config.minSeverity,
          action: config.action,
          llmScanEnabled: config.llmScan?.enabled ?? false,
          llmProvider: config.llmScan?.provider,
          llmModel: config.llmScan?.model,
        },
        metrics,
      });
    } catch (err) {
      res.status(500).json({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  // Reset metrics (requires ?confirm=yes)
  app.post("/debug/injection-stats/reset", (req, res) => {
    const confirm = req.query.confirm;
    if (confirm !== "yes") {
      res.status(400).json({
        ok: false,
        error: "Add ?confirm=yes to reset metrics",
      });
      return;
    }

    try {
      resetInjectionScanMetrics();
      res.json({
        ok: true,
        message: "Metrics reset successfully",
        metrics: getInjectionScanMetrics(),
      });
    } catch (err) {
      res.status(500).json({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });
}
