import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

router.get("/", async (req, res) => {
  const cases = await prisma.useCase.findMany()
  res.json(cases)
})

router.post("/", async (req, res) => {
  const { title, description, mitre } = req.body

  const newCase = await prisma.useCase.create({
    data: {
      title,
      description,
      mitre
    }
  })

  res.json(newCase)
})

export default router
