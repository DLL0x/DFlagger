import express from "express"
import cors from "cors"
import dotenv from "dotenv"

import sigmaRoutes from "./routes/sigmaRoutes"
import yaraRoutes from "./routes/yaraRoutes"
import useCaseRoutes from "./routes/useCaseRoutes"
import activityRoutes from "./routes/activityRoutes"
import dashboardRoutes from "./routes/dashboardRoutes"
import settingsRoutes from "./routes/settingsRoutes"

dotenv.config()

const app = express()

app.use(cors())
app.use(express.json())

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "DFlagger backend running",
    timestamp: new Date().toISOString(),
    version: "1.0.0"
  })
})

// API Routes
app.use("/api/sigma", sigmaRoutes)
app.use("/api/yara", yaraRoutes)
app.use("/api/usecases", useCaseRoutes)
app.use("/api/activities", activityRoutes)
app.use("/api/dashboard", dashboardRoutes)
app.use("/api/settings", settingsRoutes)

// Dashboard-related endpoints (aliases for dashboard routes)
app.use("/api/alerts", dashboardRoutes)
app.use("/api/analytics", dashboardRoutes)

// Admin routes (aliases to settings routes)
app.use("/api/adwhmin", settingsRoutes)

// Error handling middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error("Unhandled error:", err)
  res.status(500).json({ 
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined
  })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" })
})

const PORT = process.env.PORT || 4000

app.listen(PORT, () => {
  console.log(`🚀 DFlagger Server running on port ${PORT}`)
  console.log(`📊 Dashboard API: http://localhost:${PORT}/api/dashboard`)
  console.log(`🔍 Activities API: http://localhost:${PORT}/api/activities`)
  console.log(`⚙️  Settings API: http://localhost:${PORT}/api/settings`)
})
