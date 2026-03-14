import express from "express"
import cors from "cors"
import dotenv from "dotenv"

import sigmaRoutes from "./routes/sigmaRoutes"
import yaraRoutes from "./routes/yaraRoutes"
import useCaseRoutes from "./routes/useCaseRoutes"

dotenv.config()

const app = express()

app.use(cors())
app.use(express.json())

app.get("/api/health", (req, res) => {
  res.json({ status: "DFlagger backend running" })
})

app.use("/api/sigma", sigmaRoutes)
app.use("/api/yara", yaraRoutes)
app.use("/api/usecases", useCaseRoutes)

const PORT = process.env.PORT || 4000

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
