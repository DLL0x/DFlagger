import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// GET /api/sigma - Get all Sigma rules
router.get("/", async (req, res) => {
  try {
    const { page = "1", limit = "20", search, level, status, tags } = req.query

    const pageNum = parseInt(page as string)
    const limitNum = parseInt(limit as string)
    const skip = (pageNum - 1) * limitNum

    const where: any = {}

    if (level) where.level = level
    if (status) where.status = status
    if (tags) where.tags = { hasSome: (tags as string).split(",") }

    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: "insensitive" } },
        { description: { contains: search as string, mode: "insensitive" } },
        { author: { contains: search as string, mode: "insensitive" } }
      ]
    }

    const [rules, total] = await Promise.all([
      prisma.sigmaRule.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limitNum
      }),
      prisma.sigmaRule.count({ where })
    ])

    res.json({
      rules,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum)
      }
    })
  } catch (error) {
    console.error("Error fetching Sigma rules:", error)
    res.status(500).json({ error: "Failed to fetch Sigma rules" })
  }
})

// GET /api/sigma/stats - Get Sigma rule statistics
router.get("/stats", async (req, res) => {
  try {
    const [total, byLevel, byStatus, recent] = await Promise.all([
      prisma.sigmaRule.count(),
      prisma.sigmaRule.groupBy({
        by: ["level"],
        _count: { level: true }
      }),
      prisma.sigmaRule.groupBy({
        by: ["status"],
        _count: { status: true }
      }),
      prisma.sigmaRule.count({
        where: {
          createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      })
    ])

    res.json({
      total,
      byLevel: byLevel.map(l => ({ level: l.level, count: l._count.level })),
      byStatus: byStatus.map(s => ({ status: s.status, count: s._count.status })),
      recent
    })
  } catch (error) {
    console.error("Error fetching Sigma stats:", error)
    res.status(500).json({ error: "Failed to fetch Sigma stats" })
  }
})

// GET /api/sigma/:id - Get single Sigma rule
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params

    const rule = await prisma.sigmaRule.findUnique({
      where: { id }
    })

    if (!rule) {
      return res.status(404).json({ error: "Sigma rule not found" })
    }

    res.json(rule)
  } catch (error) {
    console.error("Error fetching Sigma rule:", error)
    res.status(500).json({ error: "Failed to fetch Sigma rule" })
  }
})

// POST /api/sigma - Create new Sigma rule
router.post("/", async (req, res) => {
  try {
    const {
      title,
      description,
      rule,
      level,
      status,
      tags,
      author,
      references,
      logsource,
      detection,
      condition,
      fields,
      falsepositives
    } = req.body

    const newRule = await prisma.sigmaRule.create({
      data: {
        title,
        description,
        rule,
        level: level || "medium",
        status: status || "experimental",
        tags: tags || [],
        author: author || "Security Analyst",
        references: references || [],
        logsource,
        detection,
        condition,
        fields: fields || [],
        falsepositives: falsepositives || []
      }
    })

    res.status(201).json(newRule)
  } catch (error) {
    console.error("Error creating Sigma rule:", error)
    res.status(500).json({ error: "Failed to create Sigma rule" })
  }
})

// PUT /api/sigma/:id - Update Sigma rule
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params
    const {
      title,
      description,
      rule,
      level,
      status,
      tags,
      author,
      references,
      logsource,
      detection,
      condition,
      fields,
      falsepositives
    } = req.body

    const updated = await prisma.sigmaRule.update({
      where: { id },
      data: {
        title,
        description,
        rule,
        level,
        status,
        tags,
        author,
        references,
        logsource,
        detection,
        condition,
        fields,
        falsepositives
      }
    })

    res.json(updated)
  } catch (error) {
    console.error("Error updating Sigma rule:", error)
    res.status(500).json({ error: "Failed to update Sigma rule" })
  }
})

// DELETE /api/sigma/:id - Delete Sigma rule
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params

    await prisma.sigmaRule.delete({
      where: { id }
    })

    res.json({ message: "Sigma rule deleted successfully" })
  } catch (error) {
    console.error("Error deleting Sigma rule:", error)
    res.status(500).json({ error: "Failed to delete Sigma rule" })
  }
})

// POST /api/sigma/:id/duplicate - Duplicate Sigma rule
router.post("/:id/duplicate", async (req, res) => {
  try {
    const { id } = req.params

    const original = await prisma.sigmaRule.findUnique({
      where: { id }
    })

    if (!original) {
      return res.status(404).json({ error: "Sigma rule not found" })
    }

    const duplicated = await prisma.sigmaRule.create({
      data: {
        title: `${original.title} (Copy)`,
        description: original.description,
        rule: original.rule as any,
        level: original.level,
        status: "experimental",
        tags: original.tags,
        author: original.author,
        references: original.references,
        logsource: original.logsource as any,
        detection: original.detection as any,
        condition: original.condition,
        fields: original.fields,
        falsepositives: original.falsepositives
      }
    })

    res.status(201).json(duplicated)
  } catch (error) {
    console.error("Error duplicating Sigma rule:", error)
    res.status(500).json({ error: "Failed to duplicate Sigma rule" })
  }
})

// GET /api/sigma/export/all - Export all Sigma rules
router.get("/export/all", async (req, res) => {
  try {
    const rules = await prisma.sigmaRule.findMany({
      orderBy: { createdAt: "desc" }
    })

    res.setHeader("Content-Type", "application/json")
    res.setHeader("Content-Disposition", `attachment; filename="sigma-rules-${new Date().toISOString().split("T")[0]}.json"`)
    res.json(rules)
  } catch (error) {
    console.error("Error exporting Sigma rules:", error)
    res.status(500).json({ error: "Failed to export Sigma rules" })
  }
})

export default router
