import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

router.get("/", async (req, res) => {
  const rules = await prisma.sigmaRule.findMany()
  res.json(rules)
})

router.post("/", async (req, res) => {
  const { title, description, rule } = req.body

  const newRule = await prisma.sigmaRule.create({
    data: {
      title,
      description,
      rule
    }
  })

  res.json(newRule)
})

export default router
