import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// GET /api/dashboard/stats - Get main dashboard statistics
router.get("/stats", async (req, res) => {
  try {
    const now = new Date()
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

    const [
      totalUseCases,
      yaraRules,
      sigmaRules,
      activeAlerts,
      criticalAlerts,
      activities24h,
      mitreMappings,
      recentActivities
    ] = await Promise.all([
      prisma.useCase.count(),
      prisma.yaraRule.count(),
      prisma.sigmaRule.count(),
      prisma.alert.count({ where: { status: { not: "resolved" } } }),
      prisma.alert.count({ where: { severity: "critical", status: { not: "resolved" } } }),
      prisma.activity.count({ where: { createdAt: { gte: dayAgo } } }),
      prisma.useCase.count({ where: { mitre: { not: null } } }),
      prisma.activity.findMany({
        orderBy: { createdAt: "desc" },
        take: 5,
        select: {
          id: true,
          type: true,
          title: true,
          description: true,
          user: true,
          timestamp: true,
          section: true
        }
      })
    ])

    // Calculate system health (mock calculation based on alerts)
    const systemHealth = Math.max(0, 100 - (criticalAlerts * 10))
    const uptime = "10d 12h" // This would come from actual system monitoring

    res.json({
      totalUseCases,
      yaraRules,
      sigmaRules,
      activeMonitors: 8, // Placeholder - would come from actual monitor service
      systemHealth,
      uptime,
      lolglobsCount: 45, // Placeholder - would come from LOLGlobs service
      mitreMappings,
      logParserFiles: 12, // Placeholder
      queryBuilderQueries: 34, // Placeholder
      activeAlerts,
      criticalAlerts,
      activities24h,
      recentActivities
    })
  } catch (error) {
    console.error("Error fetching dashboard stats:", error)
    res.status(500).json({ error: "Failed to fetch dashboard stats" })
  }
})

// GET /api/dashboard/section-stats - Get stats for each section
router.get("/section-stats", async (req, res) => {
  try {
    const [
      useCases,
      yara,
      sigma,
      activities
    ] = await Promise.all([
      prisma.useCase.count(),
      prisma.yaraRule.count(),
      prisma.sigmaRule.count(),
      prisma.activity.count()
    ])

    res.json({
      usecases: { count: useCases, label: "Use Cases" },
      yaragenerator: { count: yara, label: "YARA Rules" },
      sigmabuilder: { count: sigma, label: "Sigma Rules" },
      lolglobs: { count: 45, label: "LOLGlobs" },
      mitreattack: { count: 120, label: "MITRE Maps" },
      logparser: { count: 12, label: "Log Files" },
      querybuilder: { count: 34, label: "Queries" },
      activities: { count: activities, label: "Activities" }
    })
  } catch (error) {
    console.error("Error fetching section stats:", error)
    res.status(500).json({ error: "Failed to fetch section stats" })
  }
})

// GET /api/alerts/recent - Get recent alerts for dashboard
router.get("/alerts/recent", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 10

    const alerts = await prisma.alert.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
      select: {
        id: true,
        severity: true,
        title: true,
        source: true,
        status: true,
        createdAt: true
      }
    })

    // Format time as relative
    const formattedAlerts = alerts.map(alert => ({
      ...alert,
      time: getRelativeTime(alert.createdAt)
    }))

    res.json(formattedAlerts)
  } catch (error) {
    console.error("Error fetching recent alerts:", error)
    res.status(500).json({ error: "Failed to fetch recent alerts" })
  }
})

// GET /api/analytics/threats - Get threat timeline data
router.get("/analytics/threats", async (req, res) => {
  try {
    // Generate mock threat data for the last 24 hours
    const labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now"]
    
    // Get actual activity counts per time bucket
    const now = new Date()
    const buckets = labels.map((_, i) => {
      const hour = now.getHours() - (6 - i) * 4
      return new Date(now.getFullYear(), now.getMonth(), now.getDate(), hour)
    })

    const counts = await Promise.all(
      buckets.map(async (bucket, i) => {
        const nextBucket = buckets[i + 1] || new Date()
        const [critical, high] = await Promise.all([
          prisma.activity.count({
            where: {
              severity: "critical",
              createdAt: { gte: bucket, lt: nextBucket }
            }
          }),
          prisma.activity.count({
            where: {
              severity: "high",
              createdAt: { gte: bucket, lt: nextBucket }
            }
          })
        ])
        return { critical, high }
      })
    )

    // If no data, return mock data
    const hasData = counts.some(c => c.critical > 0 || c.high > 0)
    
    if (!hasData) {
      return res.json({
        labels,
        datasets: [
          {
            label: "Critical",
            data: [2, 1, 4, 3, 5, 2, 3],
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            fill: true,
            tension: 0.4
          },
          {
            label: "High",
            data: [5, 3, 7, 6, 8, 4, 6],
            borderColor: "#f97316",
            backgroundColor: "rgba(249, 115, 22, 0.1)",
            fill: true,
            tension: 0.4
          }
        ]
      })
    }

    res.json({
      labels,
      datasets: [
        {
          label: "Critical",
          data: counts.map(c => c.critical),
          borderColor: "#ef4444",
          backgroundColor: "rgba(239, 68, 68, 0.1)",
          fill: true,
          tension: 0.4
        },
        {
          label: "High",
          data: counts.map(c => c.high),
          borderColor: "#f97316",
          backgroundColor: "rgba(249, 115, 22, 0.1)",
          fill: true,
          tension: 0.4
        }
      ]
    })
  } catch (error) {
    console.error("Error fetching threat data:", error)
    res.status(500).json({ error: "Failed to fetch threat data" })
  }
})

// GET /api/analytics/severity - Get severity distribution
router.get("/analytics/severity", async (req, res) => {
  try {
    const distribution = await prisma.alert.groupBy({
      by: ["severity"],
      _count: { severity: true }
    })

    const severityMap: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }

    distribution.forEach(d => {
      severityMap[d.severity] = d._count.severity
    })

    // If no data, return mock data
    if (distribution.length === 0) {
      return res.json({
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [12, 28, 45, 35],
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
          borderWidth: 0
        }]
      })
    }

    res.json({
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [
          severityMap.critical,
          severityMap.high,
          severityMap.medium,
          severityMap.low
        ],
        backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
        borderWidth: 0
      }]
    })
  } catch (error) {
    console.error("Error fetching severity distribution:", error)
    res.status(500).json({ error: "Failed to fetch severity distribution" })
  }
})

// GET /api/analytics/detections - Get top detection categories
router.get("/analytics/detections", async (req, res) => {
  try {
    // Get detection counts by type
    const detections = await prisma.activity.groupBy({
      by: ["type"],
      where: { type: { in: ["detection", "alert", "use_case"] } },
      _count: { type: true }
    })

    // If no data, return mock data
    if (detections.length === 0) {
      return res.json({
        labels: ["PowerShell", "WMI", "Registry", "Network", "Process", "File"],
        datasets: [{
          label: "Detections",
          data: [45, 32, 28, 38, 42, 25],
          backgroundColor: "rgba(34, 211, 238, 0.6)",
          borderColor: "#22d3ee",
          borderWidth: 1,
          borderRadius: 4
        }]
      })
    }

    res.json({
      labels: detections.map(d => d.type),
      datasets: [{
        label: "Detections",
        data: detections.map(d => d._count.type),
        backgroundColor: "rgba(34, 211, 238, 0.6)",
        borderColor: "#22d3ee",
        borderWidth: 1,
        borderRadius: 4
      }]
    })
  } catch (error) {
    console.error("Error fetching detection analytics:", error)
    res.status(500).json({ error: "Failed to fetch detection analytics" })
  }
})

// GET /api/dashboard/health - Get system health status
router.get("/health", async (req, res) => {
  try {
    const [
      dbHealth,
      recentErrors,
      pendingAlerts
    ] = await Promise.all([
      prisma.$queryRaw`SELECT 1`.then(() => true).catch(() => false),
      prisma.activity.count({
        where: {
          status: "error",
          createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        }
      }),
      prisma.alert.count({ where: { status: "new" } })
    ])

    const health = {
      database: dbHealth ? "healthy" : "unhealthy",
      status: recentErrors > 10 || pendingAlerts > 50 ? "degraded" : "healthy",
      recentErrors,
      pendingAlerts,
      timestamp: new Date().toISOString()
    }

    res.json(health)
  } catch (error) {
    console.error("Error fetching health status:", error)
    res.status(500).json({ error: "Failed to fetch health status" })
  }
})

// Helper function to get relative time
function getRelativeTime(date: Date): string {
  const now = new Date()
  const diff = now.getTime() - new Date(date).getTime()
  const minutes = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)

  if (minutes < 1) return "Just now"
  if (minutes < 60) return `${minutes} min ago`
  if (hours < 24) return `${hours} hour${hours > 1 ? "s" : ""} ago`
  if (days < 7) return `${days} day${days > 1 ? "s" : ""} ago`
  return new Date(date).toLocaleDateString()
}

export default router
