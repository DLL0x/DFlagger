import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// GET /api/activities - Get all activities with filtering and pagination
router.get("/", async (req, res) => {
  try {
    const {
      page = "1",
      limit = "20",
      search,
      type,
      severity,
      startDate,
      endDate,
      userId,
      section
    } = req.query

    const pageNum = parseInt(page as string)
    const limitNum = parseInt(limit as string)
    const skip = (pageNum - 1) * limitNum

    // Build where clause
    const where: any = {}

    if (type && type !== "all") {
      where.type = type
    }

    if (severity && severity !== "all") {
      where.severity = severity
    }

    if (userId) {
      where.userId = userId
    }

    if (section) {
      where.section = section
    }

    if (startDate || endDate) {
      where.createdAt = {}
      if (startDate) {
        where.createdAt.gte = new Date(startDate as string)
      }
      if (endDate) {
        where.createdAt.lte = new Date(endDate as string)
      }
    }

    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: "insensitive" } },
        { description: { contains: search as string, mode: "insensitive" } },
        { user: { contains: search as string, mode: "insensitive" } },
        { ipAddress: { contains: search as string, mode: "insensitive" } }
      ]
    }

    const [activities, total] = await Promise.all([
      prisma.activity.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limitNum,
        include: {
          userRelation: {
            select: {
              id: true,
              email: true,
              name: true
            }
          }
        }
      }),
      prisma.activity.count({ where })
    ])

    res.json({
      activities,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum)
      }
    })
  } catch (error) {
    console.error("Error fetching activities:", error)
    res.status(500).json({ error: "Failed to fetch activities" })
  }
})

// GET /api/activities/recent - Get recent activities for dashboard
router.get("/recent", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 10

    const activities = await prisma.activity.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
      select: {
        id: true,
        type: true,
        title: true,
        description: true,
        user: true,
        section: true,
        severity: true,
        createdAt: true
      }
    })

    res.json(activities)
  } catch (error) {
    console.error("Error fetching recent activities:", error)
    res.status(500).json({ error: "Failed to fetch recent activities" })
  }
})

// GET /api/activities/stats - Get activity statistics
router.get("/stats", async (req, res) => {
  try {
    const now = new Date()
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

    const [
      totalCount,
      last24hCount,
      last7dCount,
      typeCounts,
      severityCounts
    ] = await Promise.all([
      prisma.activity.count(),
      prisma.activity.count({
        where: { createdAt: { gte: dayAgo } }
      }),
      prisma.activity.count({
        where: { createdAt: { gte: weekAgo } }
      }),
      prisma.activity.groupBy({
        by: ["type"],
        _count: { type: true }
      }),
      prisma.activity.groupBy({
        by: ["severity"],
        _count: { severity: true }
      })
    ])

    res.json({
      total: totalCount,
      last24h: last24hCount,
      last7d: last7dCount,
      byType: typeCounts.map(t => ({ type: t.type, count: t._count.type })),
      bySeverity: severityCounts.map(s => ({ severity: s.severity, count: s._count.severity }))
    })
  } catch (error) {
    console.error("Error fetching activity stats:", error)
    res.status(500).json({ error: "Failed to fetch activity stats" })
  }
})

// GET /api/activities/:id - Get single activity
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params

    const activity = await prisma.activity.findUnique({
      where: { id },
      include: {
        userRelation: {
          select: {
            id: true,
            email: true,
            name: true,
            role: true
          }
        }
      }
    })

    if (!activity) {
      return res.status(404).json({ error: "Activity not found" })
    }

    res.json(activity)
  } catch (error) {
    console.error("Error fetching activity:", error)
    res.status(500).json({ error: "Failed to fetch activity" })
  }
})

// POST /api/activities - Create new activity
router.post("/", async (req, res) => {
  try {
    const {
      type,
      title,
      description,
      user,
      userId,
      severity,
      status,
      ipAddress,
      userAgent,
      section,
      metadata,
      resourceId,
      resourceType,
      changes
    } = req.body

    const activity = await prisma.activity.create({
      data: {
        type,
        title,
        description,
        user: user || "System",
        userId,
        severity,
        status,
        ipAddress,
        userAgent,
        section,
        metadata,
        resourceId,
        resourceType,
        changes
      }
    })

    res.status(201).json(activity)
  } catch (error) {
    console.error("Error creating activity:", error)
    res.status(500).json({ error: "Failed to create activity" })
  }
})

// POST /api/activities/bulk - Create multiple activities
router.post("/bulk", async (req, res) => {
  try {
    const { activities } = req.body

    if (!Array.isArray(activities)) {
      return res.status(400).json({ error: "Activities must be an array" })
    }

    const created = await prisma.$transaction(
      activities.map(activity => prisma.activity.create({ data: activity }))
    )

    res.status(201).json({ count: created.length, activities: created })
  } catch (error) {
    console.error("Error creating bulk activities:", error)
    res.status(500).json({ error: "Failed to create activities" })
  }
})

// DELETE /api/activities/:id - Delete activity
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params

    await prisma.activity.delete({
      where: { id }
    })

    res.json({ message: "Activity deleted successfully" })
  } catch (error) {
    console.error("Error deleting activity:", error)
    res.status(500).json({ error: "Failed to delete activity" })
  }
})

// DELETE /api/activities - Delete old activities (for data retention)
router.delete("/", async (req, res) => {
  try {
    const { olderThan } = req.query

    if (!olderThan) {
      return res.status(400).json({ error: "olderThan date is required" })
    }

    const cutoffDate = new Date(olderThan as string)

    const result = await prisma.activity.deleteMany({
      where: { createdAt: { lt: cutoffDate } }
    })

    res.json({ message: `Deleted ${result.count} activities` })
  } catch (error) {
    console.error("Error deleting old activities:", error)
    res.status(500).json({ error: "Failed to delete activities" })
  }
})

// GET /api/activities/export - Export activities to CSV
router.get("/export", async (req, res) => {
  try {
    const { search, type, severity, startDate, endDate } = req.query

    const where: any = {}

    if (type && type !== "all") where.type = type
    if (severity && severity !== "all") where.severity = severity
    if (startDate || endDate) {
      where.createdAt = {}
      if (startDate) where.createdAt.gte = new Date(startDate as string)
      if (endDate) where.createdAt.lte = new Date(endDate as string)
    }

    const activities = await prisma.activity.findMany({
      where,
      orderBy: { createdAt: "desc" }
    })

    // Convert to CSV
    const headers = ["ID", "Type", "Title", "Description", "User", "Severity", "Status", "IP Address", "Timestamp"]
    const rows = activities.map(a => [
      a.id,
      a.type,
      `"${a.title.replace(/"/g, '""')}"`,
      `"${a.description.replace(/"/g, '""')}"`,
      a.user,
      a.severity || "",
      a.status || "",
      a.ipAddress || "",
      a.createdAt.toISOString()
    ])

    const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n")

    res.setHeader("Content-Type", "text/csv")
    res.setHeader("Content-Disposition", `attachment; filename="audit-log-${new Date().toISOString().split("T")[0]}.csv"`)
    res.send(csv)
  } catch (error) {
    console.error("Error exporting activities:", error)
    res.status(500).json({ error: "Failed to export activities" })
  }
})

export default router
