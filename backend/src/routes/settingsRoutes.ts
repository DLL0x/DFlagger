import { Router } from "express"
import { prisma } from "../config/prisma"

const router = Router()

// ==================== SETTINGS MANAGEMENT ====================

// GET /api/settings - Get all settings or filter by category
router.get("/", async (req, res) => {
  try {
    const { category } = req.query
    
    const where = category ? { category: category as string } : {}
    
    const settings = await prisma.setting.findMany({
      where,
      orderBy: { category: "asc" }
    })

    res.json(settings)
  } catch (error) {
    console.error("Error fetching settings:", error)
    res.status(500).json({ error: "Failed to fetch settings" })
  }
})

// GET /api/settings/:key - Get specific setting
router.get("/:key", async (req, res) => {
  try {
    const { key } = req.params

    const setting = await prisma.setting.findUnique({
      where: { key }
    })

    if (!setting) {
      return res.status(404).json({ error: "Setting not found" })
    }

    res.json(setting)
  } catch (error) {
    console.error("Error fetching setting:", error)
    res.status(500).json({ error: "Failed to fetch setting" })
  }
})

// POST /api/settings - Create or update setting
router.post("/", async (req, res) => {
  try {
    const { category, key, value, description, isEncrypted } = req.body

    const setting = await prisma.setting.upsert({
      where: { key },
      update: {
        value,
        description,
        isEncrypted: isEncrypted || false
      },
      create: {
        category,
        key,
        value,
        description,
        isEncrypted: isEncrypted || false
      }
    })

    res.json(setting)
  } catch (error) {
    console.error("Error saving setting:", error)
    res.status(500).json({ error: "Failed to save setting" })
  }
})

// PUT /api/settings/:key - Update specific setting
router.put("/:key", async (req, res) => {
  try {
    const { key } = req.params
    const { value, description } = req.body

    const setting = await prisma.setting.update({
      where: { key },
      data: { value, description }
    })

    res.json(setting)
  } catch (error) {
    console.error("Error updating setting:", error)
    res.status(500).json({ error: "Failed to update setting" })
  }
})

// PUT /api/settings/bulk - Update multiple settings
router.put("/bulk", async (req, res) => {
  try {
    const { settings } = req.body

    if (!Array.isArray(settings)) {
      return res.status(400).json({ error: "Settings must be an array" })
    }

    const updated = await prisma.$transaction(
      settings.map(s => 
        prisma.setting.upsert({
          where: { key: s.key },
          update: { value: s.value },
          create: {
            category: s.category,
            key: s.key,
            value: s.value,
            description: s.description
          }
        })
      )
    )

    res.json({ count: updated.length, settings: updated })
  } catch (error) {
    console.error("Error updating settings:", error)
    res.status(500).json({ error: "Failed to update settings" })
  }
})

// DELETE /api/settings/:key - Delete setting
router.delete("/:key", async (req, res) => {
  try {
    const { key } = req.params

    await prisma.setting.delete({
      where: { key }
    })

    res.json({ message: "Setting deleted successfully" })
  } catch (error) {
    console.error("Error deleting setting:", error)
    res.status(500).json({ error: "Failed to delete setting" })
  }
})

// ==================== USER MANAGEMENT ====================

// GET /api/admin/users - Get all users
router.get("/admin/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        mfaEnabled: true,
        lastLogin: true,
        createdAt: true
      }
    })

    res.json({ users })
  } catch (error) {
    console.error("Error fetching users:", error)
    res.status(500).json({ error: "Failed to fetch users" })
  }
})

// GET /api/admin/users/:id - Get specific user
router.get("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        mfaEnabled: true,
        lastLogin: true,
        createdAt: true
      }
    })

    if (!user) {
      return res.status(404).json({ error: "User not found" })
    }

    res.json(user)
  } catch (error) {
    console.error("Error fetching user:", error)
    res.status(500).json({ error: "Failed to fetch user" })
  }
})

// POST /api/admin/users - Create user
router.post("/admin/users", async (req, res) => {
  try {
    const { email, password, name, role, mfaEnabled } = req.body

    // Check if email exists
    const existing = await prisma.user.findUnique({ where: { email } })
    if (existing) {
      return res.status(400).json({ error: "Email already exists" })
    }

    const user = await prisma.user.create({
      data: {
        email,
        password, // Should be hashed in production
        name,
        role: role || "analyst",
        mfaEnabled: mfaEnabled || false
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        mfaEnabled: true,
        createdAt: true
      }
    })

    res.status(201).json(user)
  } catch (error) {
    console.error("Error creating user:", error)
    res.status(500).json({ error: "Failed to create user" })
  }
})

// PUT /api/admin/users/:id - Update user
router.put("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params
    const { name, role, status, mfaEnabled } = req.body

    const user = await prisma.user.update({
      where: { id },
      data: {
        name,
        role,
        status,
        mfaEnabled
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        status: true,
        mfaEnabled: true,
        lastLogin: true,
        updatedAt: true
      }
    })

    res.json(user)
  } catch (error) {
    console.error("Error updating user:", error)
    res.status(500).json({ error: "Failed to update user" })
  }
})

// DELETE /api/admin/users/:id - Delete user
router.delete("/admin/users/:id", async (req, res) => {
  try {
    const { id } = req.params

    await prisma.user.delete({
      where: { id }
    })

    res.json({ message: "User deleted successfully" })
  } catch (error) {
    console.error("Error deleting user:", error)
    res.status(500).json({ error: "Failed to delete user" })
  }
})

// ==================== ROLE MANAGEMENT ====================

// GET /api/admin/roles - Get all roles
router.get("/admin/roles", async (req, res) => {
  try {
    const roles = await prisma.role.findMany({
      orderBy: { createdAt: "desc" }
    })

    // Get user count for each role
    const rolesWithCount = await Promise.all(
      roles.map(async (role) => {
        const count = await prisma.user.count({ where: { role: role.name } })
        return { ...role, userCount: count }
      })
    )

    res.json({ roles: rolesWithCount })
  } catch (error) {
    console.error("Error fetching roles:", error)
    res.status(500).json({ error: "Failed to fetch roles" })
  }
})

// GET /api/admin/roles/:id - Get specific role
router.get("/admin/roles/:id", async (req, res) => {
  try {
    const { id } = req.params

    const role = await prisma.role.findUnique({
      where: { id }
    })

    if (!role) {
      return res.status(404).json({ error: "Role not found" })
    }

    const userCount = await prisma.user.count({ where: { role: role.name } })

    res.json({ ...role, userCount })
  } catch (error) {
    console.error("Error fetching role:", error)
    res.status(500).json({ error: "Failed to fetch role" })
  }
})

// POST /api/admin/roles - Create role
router.post("/admin/roles", async (req, res) => {
  try {
    const { name, description, permissions } = req.body

    // Check if name exists
    const existing = await prisma.role.findUnique({ where: { name } })
    if (existing) {
      return res.status(400).json({ error: "Role name already exists" })
    }

    const role = await prisma.role.create({
      data: {
        name,
        description,
        permissions: permissions || [],
        isSystem: false
      }
    })

    res.status(201).json(role)
  } catch (error) {
    console.error("Error creating role:", error)
    res.status(500).json({ error: "Failed to create role" })
  }
})

// PUT /api/admin/roles/:id - Update role
router.put("/admin/roles/:id", async (req, res) => {
  try {
    const { id } = req.params
    const { name, description, permissions } = req.body

    const role = await prisma.role.update({
      where: { id },
      data: {
        name,
        description,
        permissions
      }
    })

    res.json(role)
  } catch (error) {
    console.error("Error updating role:", error)
    res.status(500).json({ error: "Failed to update role" })
  }
})

// DELETE /api/admin/roles/:id - Delete role
router.delete("/admin/roles/:id", async (req, res) => {
  try {
    const { id } = req.params

    const role = await prisma.role.findUnique({ where: { id } })
    if (role?.isSystem) {
      return res.status(400).json({ error: "Cannot delete system role" })
    }

    await prisma.role.delete({
      where: { id }
    })

    res.json({ message: "Role deleted successfully" })
  } catch (error) {
    console.error("Error deleting role:", error)
    res.status(500).json({ error: "Failed to delete role" })
  }
})

// ==================== SECURITY SETTINGS ====================

// GET /api/admin/security-settings - Get all security settings
router.get("/admin/security-settings", async (req, res) => {
  try {
    const security = await prisma.setting.findMany({
      where: { category: "security" }
    })

    const retention = await prisma.setting.findMany({
      where: { category: "data" }
    })

    const system = await prisma.setting.findMany({
      where: { category: "system" }
    })

    res.json({
      security: settingsToObject(security),
      retention: settingsToObject(retention),
      system: settingsToObject(system)
    })
  } catch (error) {
    console.error("Error fetching security settings:", error)
    res.status(500).json({ error: "Failed to fetch security settings" })
  }
})

// PUT /api/admin/settings/:section - Update settings by section
router.put("/admin/settings/:section", async (req, res) => {
  try {
    const { section } = req.params
    const data = req.body

    const settings = await prisma.$transaction(
      Object.entries(data).map(([key, value]) =>
        prisma.setting.upsert({
          where: { key: `${section}.${key}` },
          update: { value: typeof value === "object" ? value : { value } },
          create: {
            category: section,
            key: `${section}.${key}`,
            value: typeof value === "object" ? value : { value },
            description: `${section} setting for ${key}`
          }
        })
      )
    )

    res.json({ message: "Settings updated successfully", settings })
  } catch (error) {
    console.error("Error updating settings:", error)
    res.status(500).json({ error: "Failed to update settings" })
  }
})

// Helper function to convert settings array to object
function settingsToObject(settings: any[]) {
  const result: any = {}
  settings.forEach(s => {
    const key = s.key.split(".").pop() || s.key
    result[key] = s.value?.value ?? s.value
  })
  return result
}

export default router
