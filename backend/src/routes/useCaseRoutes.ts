import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// GET /api/usecases - Get all use cases
router.get("/", async (req, res) => {
  try {
    const { page = "1", limit = "20", search, mitre, platform, status, priority } = req.query

    const pageNum = parseInt(page as string)
    const limitNum = parseInt(limit as string)
    const skip = (pageNum - 1) * limitNum

    const where: any = {}

    if (mitre) where.mitre = { contains: mitre as string, mode: "insensitive" }
    if (platform) where.platform = platform
    if (status) where.status = status
    if (priority) where.priority = priority

    if (search) {
      where.OR = [
        { title: { contains: search as string, mode: "insensitive" } },
        { description: { contains: search as string, mode: "insensitive" } },
        { author: { contains: search as string, mode: "insensitive" } }
      ]
    }

    const [cases, total] = await Promise.all([
      prisma.useCase.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip,
        take: limitNum
      }),
      prisma.useCase.count({ where })
    ])

    res.json({
      cases,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        totalPages: Math.ceil(total / limitNum)
      }
    })
  } catch (error) {
    console.error("Error fetching use cases:", error)
    res.status(500).json({ error: "Failed to fetch use cases" })
  }
})

// GET /api/usecases/stats - Get use case statistics
router.get("/stats", async (req, res) => {
  try {
    const [total, byStatus, byPriority, withMitre, recent] = await Promise.all([
      prisma.useCase.count(),
      prisma.useCase.groupBy({
        by: ["status"],
        _count: { status: true }
      }),
      prisma.useCase.groupBy({
        by: ["priority"],
        _count: { priority: true }
      }),
      prisma.useCase.count({ where: { mitre: { not: null } } }),
      prisma.useCase.count({
        where: {
          createdAt: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
        }
      })
    ])

    res.json({
      total,
      byStatus: byStatus.map(s => ({ status: s.status, count: s._count.status })),
      byPriority: byPriority.map(p => ({ priority: p.priority, count: p._count.priority })),
      withMitre,
      recent
    })
  } catch (error) {
    console.error("Error fetching use case stats:", error)
    res.status(500).json({ error: "Failed to fetch use case stats" })
  }
})

// GET /api/usecases/mitres - Get all unique MITRE mappings
router.get("/mitres", async (req, res) => {
  try {
    const useCases = await prisma.useCase.findMany({
      where: { mitre: { not: null } },
      select: { mitre: true, mitreTactic: true, mitreTechnique: true }
    })

    const uniqueMitres = useCases.reduce((acc: any[], uc) => {
      if (uc.mitre && !acc.find(m => m.id === uc.mitre)) {
        acc.push({
          id: uc.mitre,
          tactic: uc.mitreTactic,
          technique: uc.mitreTechnique
        })
      }
      return acc
    }, [])

    res.json(uniqueMitres)
  } catch (error) {
    console.error("Error fetching MITRE mappings:", error)
    res.status(500).json({ error: "Failed to fetch MITRE mappings" })
  }
})

// GET /api/usecases/:id - Get single use case
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params

    const useCase = await prisma.useCase.findUnique({
      where: { id }
    })

    if (!useCase) {
      return res.status(404).json({ error: "Use case not found" })
    }

    res.json(useCase)
  } catch (error) {
    console.error("Error fetching use case:", error)
    res.status(500).json({ error: "Failed to fetch use case" })
  }
})

// POST /api/usecases - Create new use case
router.post("/", async (req, res) => {
  try {
    const {
      title,
      description,
      mitre,
      mitreTactic,
      mitreTechnique,
      platform,
      logsource,
      detectionLogic,
      falsepositives,
      status,
      priority,
      tags,
      author,
      tests
    } = req.body

    const newCase = await prisma.useCase.create({
      data: {
        title,
        description,
        mitre,
        mitreTactic,
        mitreTechnique,
        platform: platform || "windows",
        logsource,
        detectionLogic,
        falsepositives: falsepositives || [],
        status: status || "draft",
        priority: priority || "medium",
        tags: tags || [],
        author: author || "Security Analyst",
        tests
      }
    })

    res.status(201).json(newCase)
  } catch (error) {
    console.error("Error creating use case:", error)
    res.status(500).json({ error: "Failed to create use case" })
  }
})

// PUT /api/usecases/:id - Update use case
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params
    const {
      title,
      description,
      mitre,
      mitreTactic,
      mitreTechnique,
      platform,
      logsource,
      detectionLogic,
      falsepositives,
      status,
      priority,
      tags,
      author,
      tests
    } = req.body

    const updated = await prisma.useCase.update({
      where: { id },
      data: {
        title,
        description,
        mitre,
        mitreTactic,
        mitreTechnique,
        platform,
        logsource,
        detectionLogic,
        falsepositives,
        status,
        priority,
        tags,
        author,
        tests
      }
    })

    res.json(updated)
  } catch (error) {
    console.error("Error updating use case:", error)
    res.status(500).json({ error: "Failed to update use case" })
  }
})

// DELETE /api/usecases/:id - Delete use case
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params

    await prisma.useCase.delete({
      where: { id }
    })

    res.json({ message: "Use case deleted successfully" })
  } catch (error) {
    console.error("Error deleting use case:", error)
    res.status(500).json({ error: "Failed to delete use case" })
  }
})

// POST /api/usecases/:id/duplicate - Duplicate use case
router.post("/:id/duplicate", async (req, res) => {
  try {
    const { id } = req.params

    const original = await prisma.useCase.findUnique({
      where: { id }
    })

    if (!original) {
      return res.status(404).json({ error: "Use case not found" })
    }

    const duplicated = await prisma.useCase.create({
      data: {
        title: `${original.title} (Copy)`,
        description: original.description,
        mitre: original.mitre,
        mitreTactic: original.mitreTactic,
        mitreTechnique: original.mitreTechnique,
        platform: original.platform,
        logsource: original.logsource,
        detectionLogic: original.detectionLogic as any,
        falsepositives: original.falsepositives,
        status: "draft",
        priority: original.priority,
        tags: original.tags,
        author: original.author,
        tests: original.tests as any
      }
    })

    res.status(201).json(duplicated)
  } catch (error) {
    console.error("Error duplicating use case:", error)
    res.status(500).json({ error: "Failed to duplicate use case" })
  }
})

// POST /api/usecases/:id/tests - Add test to use case
router.post("/:id/tests", async (req, res) => {
  try {
    const { id } = req.params
    const test = req.body

    const useCase = await prisma.useCase.findUnique({
      where: { id }
    })

    if (!useCase) {
      return res.status(404).json({ error: "Use case not found" })
    }

    const existingTests = (useCase.tests as any[]) || []
    const updatedTests = [...existingTests, { ...test, id: Date.now().toString() }]

    const updated = await prisma.useCase.update({
      where: { id },
      data: { tests: updatedTests }
    })

    res.json(updated)
  } catch (error) {
    console.error("Error adding test to use case:", error)
    res.status(500).json({ error: "Failed to add test" })
  }
})

// GET /api/usecases/export/all - Export all use cases
router.get("/export/all", async (req, res) => {
  try {
    const cases = await prisma.useCase.findMany({
      orderBy: { createdAt: "desc" }
    })

    res.setHeader("Content-Type", "application/json")
    res.setHeader("Content-Disposition", `attachment; filename="use-cases-${new Date().toISOString().split("T")[0]}.json"`)
    res.json(cases)
  } catch (error) {
    console.error("Error exporting use cases:", error)
    res.status(500).json({ error: "Failed to export use cases" })
  }
})

export default router
