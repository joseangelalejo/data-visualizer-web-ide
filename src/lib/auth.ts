/**
 * Módulo de Autenticación - auth.ts
 *
 * Sistema de autenticación JWT con persistencia de usuarios en PostgreSQL (Neon).
 *
 * @author José Ángel Alejo
 * @version 3.0.0
 */

import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { neon } from '@neondatabase/serverless'

// ── Configuración JWT ────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) {
  console.warn(
    '\n⚠️  ADVERTENCIA: JWT_SECRET no está definido en las variables de entorno.\n' +
    '   Configura JWT_SECRET en tu archivo .env.local\n'
  )
}
const SECRET = JWT_SECRET || (() => { throw new Error('JWT_SECRET must be set in environment variables') })()
const JWT_EXPIRES_IN = parseInt(process.env.JWT_EXPIRES_IN || '3600', 10)

// ── Base de datos PostgreSQL (Neon) ──────────────────────────────────────────
function getDb() {
  const url = process.env.DATABASE_URL
  if (!url) throw new Error('DATABASE_URL must be set in environment variables')
  return neon(url)
}

// ── Inicializar esquema ─────────────────────────────────────────────────────
let _initialized = false
async function ensureInit(): Promise<void> {
  if (_initialized) return
  _initialized = true

  const sql = getDb()

  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id         TEXT PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `

  const rows = await sql`SELECT COUNT(*) as n FROM users`
  const count = parseInt(rows[0].n, 10)

  if (count === 0) {
    const adminHash = bcrypt.hashSync('admin123', 12)
    const user1Hash = bcrypt.hashSync('user123', 12)
    await sql`
      INSERT INTO users (id, username, email, password, role)
      VALUES ('1', 'admin', 'admin@generico.com', ${adminHash}, 'admin')
      ON CONFLICT DO NOTHING
    `
    await sql`
      INSERT INTO users (id, username, email, password, role)
      VALUES ('2', 'user1', 'user1@generico.com', ${user1Hash}, 'user')
      ON CONFLICT DO NOTHING
    `
    console.log('✅ Usuarios por defecto creados en PostgreSQL')
  }
}

// ── Tipos ────────────────────────────────────────────────────────────────────
export interface User {
  id: string
  username: string
  role: 'admin' | 'user'
  email?: string
}

export interface AuthToken {
  user: User
  iat: number
  exp: number
}

// ── Contraseñas ───────────────────────────────────────────────────────────────
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12)
}

export async function verifyPassword(password: string, hashed: string): Promise<boolean> {
  return bcrypt.compare(password, hashed)
}

// ── JWT ─────────────────────────────────────────────────────────────────────
export function generateToken(user: User): string {
  return jwt.sign(
    { user: { id: user.id, username: user.username, role: user.role } },
    SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  )
}

export function verifyToken(token: string): AuthToken | null {
  try {
    return jwt.verify(token, SECRET) as AuthToken
  } catch {
    return null
  }
}

// ── CRUD usuarios ─────────────────────────────────────────────────────────────
export async function authenticateUser(username: string, password: string): Promise<User | null> {
  await ensureInit()
  const sql = getDb()
  const rows = await sql`SELECT * FROM users WHERE username = ${username}`
  const row = rows[0]
  if (!row) return null
  const valid = await verifyPassword(password, row.password)
  if (!valid) return null
  return { id: row.id, username: row.username, role: row.role, email: row.email }
}

export async function registerUser(username: string, email: string, password: string): Promise<User> {
  if (!username || !email || !password) throw new Error('Faltan campos obligatorios')
  await ensureInit()

  const sql = getDb()

  const existsByUsername = await sql`SELECT id FROM users WHERE username = ${username}`
  if (existsByUsername.length > 0) throw new Error('El nombre de usuario ya existe')

  const existsByEmail = await sql`SELECT id FROM users WHERE email = ${email}`
  if (existsByEmail.length > 0) throw new Error('El email ya está en uso')

  const hashed = await hashPassword(password)
  const id = crypto.randomUUID()
  await sql`
    INSERT INTO users (id, username, email, password, role)
    VALUES (${id}, ${username.trim()}, ${email.trim()}, ${hashed}, 'user')
  `
  return { id, username: username.trim(), role: 'user', email: email.trim() }
}

// ── Auth middleware ───────────────────────────────────────────────────────────
export function requireAuth(request: Request): User {
  const authHeader = request.headers.get('Authorization')
  if (!authHeader?.startsWith('Bearer ')) throw new Error('No se proporcionó token de autorización')
  const token = authHeader.substring(7)
  const decoded = verifyToken(token)
  if (!decoded) throw new Error('Token inválido o expirado')
  return decoded.user
}

export function requireAdmin(user: User): void {
  if (user.role !== 'admin') throw new Error('Se requieren permisos de administrador')
}