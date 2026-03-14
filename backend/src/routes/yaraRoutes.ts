import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// GET /api/yara - Get all YARA rules
router.get("/", async (req, res) => {
  try {
    const { page = "1", limit = "20", search, level, tags } = req.query

    const pageNum = parseInt(page as string)
    const limitNum = parseInt(limit as string)
    const skip = (pageNum - 1) * limitNum

    const where: any = {}

    if (level) where.level = level
    if (tags) where.tags = { hasSome: (tags as string).split(",") }

    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: "insensitive" } },
        { description: { contains: search as string, mode: "insensitive" } },
        { author: { contains: search as string, mode: "insensitive" } }
      ]
    }

    const [rules, total] = await Promise.all([
      prisma.yaraRule.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limitNum
      }),
      prisma.yaraRule.count({ where })
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
    console.error("Error fetching YARA rules:", error)
    res.status(500).json({ error: "Failed to fetch YARA rules" })
  }
})

// GET /api/yara/stats - Get YARA rule statistics
router.get("/stats", async (req, res) => {
  try {
    const [total, byLevel, recent] = await Promise.all([
      prisma.yaraRule.count(),
      prisma.yaraRule.groupBy({
        by: ["level"],
        _count: { level: true }
      }),
      prisma.yaraRule.count({
        where: {
          createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      })
    ])

    res.json({
      total,
      byLevel: byLevel.map(l => ({ level: l.level, count: l._count.level })),
      recent
    })
  } catch (error) {
    console.error("Error fetching YARA stats:", error)
    res.status(500).json({ error: "Failed to fetch YARA stats" })
  }
})

// GET /api/yara/:id - Get single YARA rule
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params

    const rule = await prisma.yaraRule.findUnique({
      where: { id }
    })

    if (!rule) {
      return res.status(404).json({ error: "YARA rule not found" })
    }

    res.json(rule)
  } catch (error) {
    console.error("Error fetching YARA rule:", error)
    res.status(500).json({ error: "Failed to fetch YARA rule" })
  }
})

// POST /api/yara - Create new YARA rule
router.post("/", async (req, res) => {
  try {
    const {
      title,
      description,
      rule,
      level,
      tags,
      author,
      strings,
      condition,
      imports,
      version,
      reference,
      hash
    } = req.body

    const newRule = await prisma.yaraRule.create({
      data: {
        title,
        description,
        rule,
        level: level || "high",
        tags: tags || [],
        author: author || "Security Analyst",
        strings,
        condition,
        imports: imports || [],
        version: version || "1.0",
        reference,
        hash
      }
    })

    res.status(201).json(newRule)
  } catch (error) {
    console.error("Error creating YARA rule:", error)
    res.status(500).json({ error: "Failed to create YARA rule" })
  }
})

// PUT /api/yara/:id - Update YARA rule
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params
    const {
      title,
      description,
      rule,
      level,
      tags,
      author,
      strings,
      condition,
      imports,
      version,
      reference,
      hash
    } = req.body

    const updated = await prisma.yaraRule.update({
      where: { id },
      data: {
        title,
        description,
        rule,
        level,
        tags,
        author,
        strings,
        condition,
        imports,
        version,
        reference,
        hash
      }
    })

    res.json(updated)
  } catch (error) {
    console.error("Error updating YARA rule:", error)
    res.status(500).json({ error: "Failed to update YARA rule" })
  }
})

// DELETE /api/yara/:id - Delete YARA rule
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params

    await prisma.yaraRule.delete({
      where: { id }
    })

    res.json({ message: "YARA rule deleted successfully" })
  } catch (error) {
    console.error("Error deleting YARA rule:", error)
    res.status(500).json({ error: "Failed to delete YARA rule" })
  }
})

// POST /api/yara/:id/duplicate - Duplicate YARA rule
router.post("/:id/duplicate", async (req, res) => {
  try {
    const { id } = req.params

    const original = await prisma.yaraRule.findUnique({
      where: { id }
    })

    if (!original) {
      return res.status(404).json({ error: "YARA rule not found" })
    }

    const duplicated = await prisma.yaraRule.create({
      data: {
        title: `${original.title} (Copy)`,
        description: original.description,
        rule: original.rule,
        level: original.level,
        tags: original.tags,
        author: original.author,
        strings: original.strings,
        condition: original.condition,
        imports: original.imports,
        version: original.version,
        reference: original.reference,
        hash: original.hash
      }
    })

    res.status(201).json(duplicated)
  } catch (error) {
    console.error("Error duplicating YARA rule:", error)
    res.status(500).json({ error: "Failed to duplicate YARA rule" })
  }
})

// GET /api/yara/export/all - Export all YARA rules
router.get("/export/all", async (req, res) => {
  try {
    const rules = await prisma.yaraRule.findMany({
      orderBy: { createdAt: "desc" }
    })

    res.setHeader("Content-Type", "application/json")
    res.setHeader("Content-Disposition", `attachment; filename="yara-rules-${new Date().toISOString().split("T")[0]}.json"`)
    res.json(rules)
  } catch (error) {
    console.error("Error exporting YARA rules:", error)
    res.status(500).json({ error: "Failed to export YARA rules" })
  }
})

export default router
