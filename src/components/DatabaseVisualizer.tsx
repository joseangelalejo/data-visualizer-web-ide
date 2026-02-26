'use client'

/**
 * DatabaseVisualizer — Conexión y exploración de bases de datos.
 *
 * Soporta: SQLite, PostgreSQL, MySQL, MongoDB, MSSQL.
 * Iconos migrados de icons8 (URLs externas) a lucide-react.
 *
 * @author José Ángel Alejo
 * @version 2.0.0
 */

import React, { useState, useEffect } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import {
  useReactTable, getCoreRowModel, getFilteredRowModel,
  getSortedRowModel, getPaginationRowModel, flexRender, ColumnDef,
} from '@tanstack/react-table'
import { ReactFlow, MiniMap, Controls, Background } from '@xyflow/react'
import type { Node, Edge } from '@xyflow/react'
import {
  Link2, GitFork, Table2, BarChart2, Download, Database,
  BookMarked, RefreshCw, PlugZap,
} from 'lucide-react'
import DatabaseSidebar from './DatabaseSidebar'
import TableFilters from './TableFilters'
import ProtectedInput from './ProtectedInput'
import ProtectedSelect from './ProtectedSelect'
import { SavedConnection } from '@/lib/database-connections'

interface DataRow {
  [key: string]: string | number
}

interface TableSchema {
  name: string
  columns: { name: string; type: string }[]
}

export default function DatabaseVisualizer({ token }: { token: string }) {
  // ── Estado de conexión ───────────────────────────────────────────────────
  const [dbType, setDbType] = useState<'sqlite' | 'postgres' | 'mysql' | 'mongodb' | 'mssql'>('sqlite')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [database, setDatabase] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [sqlitePath, setSqlitePath] = useState('')

  // ── Estado de datos ──────────────────────────────────────────────────────
  const [isConnected, setIsConnected] = useState(false)
  const [tables, setTables] = useState<string[]>([])
  const [selectedTable, setSelectedTable] = useState('')
  const [data, setData] = useState<DataRow[]>([])
  const [columns, setColumns] = useState<ColumnDef<DataRow>[]>([])
  const [chartData, setChartData] = useState<{ name: string; value: number }[]>([])
  const [schema, setSchema] = useState<TableSchema[]>([])
  const [nodes, setNodes] = useState<Node[]>([])
  const [edges, setEdges] = useState<Edge[]>([])

  // ── Estado de UI ─────────────────────────────────────────────────────────
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [currentSavedConnection, setCurrentSavedConnection] = useState<SavedConnection | null>(null)
  const [globalFilter, setGlobalFilter] = useState('')
  const [savedConnections, setSavedConnections] = useState<SavedConnection[]>([])
  const [databases, setDatabases] = useState<string[] | null>(null)
  const [loadingDbs, setLoadingDbs] = useState(false)
  const [dbsError, setDbsError] = useState<string | null>(null)

  // ── Guard de autenticación ───────────────────────────────────────────────
  if (!token) {
    return (
      <div className="text-center py-12">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 max-w-md mx-auto">
          <h3 className="text-lg font-semibold text-red-800 mb-2">🔐 Autenticación Requerida</h3>
          <p className="text-red-600">Debes iniciar sesión para acceder a las funciones de base de datos.</p>
        </div>
      </div>
    )
  }

  // ── API helpers ──────────────────────────────────────────────────────────
  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  }

  const buildConnectionPayload = (overrideDb?: string) => {
    const effectiveDb = overrideDb ?? database
    if (dbType === 'sqlite') return { connectionString: sqlitePath }
    if (dbType === 'mysql') return { config: { host, user: username, password, database: effectiveDb, port: parseInt(port) || 3306 } }
    return { connectionString: `${dbType}://${username}:${password}@${host}:${port}/${effectiveDb}?sslmode=require` }
  }

  const fetchSavedConnections = async () => {
    try {
      const res = await fetch('/api/db/connections', { headers: authHeaders })
      if (res.ok) {
        const json = await res.json()
        setSavedConnections(json.connections || [])
      }
    } catch (err) {
      console.error('Error cargando conexiones guardadas:', err)
    }
  }

  useEffect(() => { if (token) fetchSavedConnections() }, [token])

  // ── Listar bases de datos disponibles ────────────────────────────────────
  const fetchDatabases = async (overrideDb?: string) => {
    if (!isConnected || !token || dbType === 'sqlite') { setDatabases([]); return }

    let sql: string | null = null
    if (dbType === 'mysql')    sql = 'SHOW DATABASES'
    if (dbType === 'postgres') sql = "SELECT datname FROM pg_database WHERE datistemplate = false AND has_database_privilege(datname, 'CONNECT')"
    if (dbType === 'mongodb')  sql = '__LIST_DATABASES__'
    if (dbType === 'mssql')    sql = 'SELECT name FROM sys.databases WHERE HAS_DBACCESS(name) = 1'
    if (!sql) { setDatabases([]); return }

    setLoadingDbs(true)
    setDbsError(null)
    try {
      const payload = { dbType, query: sql, ...buildConnectionPayload(overrideDb) }
      const res = await fetch('/api/db/query', { method: 'POST', headers: authHeaders, body: JSON.stringify(payload) })
      if (!res.ok) throw new Error(await res.text())
      const json = await res.json()
      const names = (json.data || [])
        .map((r: Record<string, unknown>) => r?.name ?? r?.datname ?? r?.NAME ?? Object.values(r)[0] ?? '')
        .filter(Boolean) as string[]
      setDatabases(names)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error al listar bases de datos'
      setDbsError(msg)
      setDatabases([])
    } finally {
      setLoadingDbs(false)
    }
  }

  useEffect(() => { if (isConnected) fetchDatabases() }, [isConnected])

  // ── Conectar ─────────────────────────────────────────────────────────────
  const connectToDatabase = async () => {
    try {
      const res = await fetch('/api/db/connect', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ dbType, ...buildConnectionPayload() }),
      })
      if (res.ok) {
        setIsConnected(true)
        await fetchDatabases()
        await loadTables()
        await loadSchema()
      } else {
        const err = await res.json()
        let msg = err.error || 'Error desconocido'
        if (res.status === 401) msg = 'Sesión expirada. Por favor, inicia sesión nuevamente.'
        if (res.status === 403) msg = 'No tienes permisos para acceder a esta función.'
        alert(`Error de conexión: ${msg}`)
      }
    } catch (err: unknown) {
      alert(`Error conectando: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const loadTables = async (overrideDb?: string) => {
    const res = await fetch('/api/db/tables', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ dbType, ...buildConnectionPayload(overrideDb) }),
    })
    const result = await res.json()
    setTables(result.tables || [])
  }

  const loadSchema = async (overrideDb?: string) => {
    const res = await fetch('/api/db/schema', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ dbType, ...buildConnectionPayload(overrideDb) }),
    })
    const result = await res.json()
    setSchema(result.schema || [])
    generateERDiagram(result.schema || [])
  }

  const loadTableData = async (tableName: string, overrideDb?: string) => {
    const res = await fetch('/api/db/query', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ dbType, query: `SELECT * FROM ${tableName} LIMIT 100`, ...buildConnectionPayload(overrideDb) }),
    })
    const result = await res.json()
    const rows: DataRow[] = result.data || []
    setData(rows)
    if (rows.length > 0) {
      setColumns(Object.keys(rows[0]).map(key => ({ accessorKey: key, header: key })))
      const firstKey = Object.keys(rows[0])[0]
      const counts: Record<string, number> = {}
      rows.forEach(row => { const v = String(row[firstKey]); counts[v] = (counts[v] || 0) + 1 })
      setChartData(Object.entries(counts).map(([name, value]) => ({ name, value })))
    }
  }

  const generateERDiagram = (schemaData: TableSchema[]) => {
    setNodes(schemaData.map((t, i) => ({
      id: t.name,
      data: { label: t.name },
      position: { x: (i % 3) * 220, y: Math.floor(i / 3) * 120 },
      style: {
        cursor: 'pointer',
        background: '#f5f3ff',
        border: '2px solid #8b5cf6',
        borderRadius: '10px',
        padding: '10px 16px',
        fontWeight: '600',
        color: '#5b21b6',
        fontSize: '13px',
      },
    })))
    setEdges([])
  }

  const exportData = () => {
    const csv = data.map(row => Object.values(row).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${selectedTable}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleDatabaseSelect = async (dbName: string) => {
    setDatabase(dbName)
    if (currentSavedConnection?.id) {
      try {
        const res = await fetch(`/api/db/connections/${currentSavedConnection.id}`, {
          method: 'PUT',
          headers: authHeaders,
          body: JSON.stringify({ database: dbName }),
        })
        if (res.ok) {
          const json = await res.json()
          const updated = json.connection || { ...currentSavedConnection, database: dbName }
          setCurrentSavedConnection(updated)
          setSavedConnections(prev => prev.map(c => c.id === updated.id ? updated : c))
        }
      } catch (err) {
        console.error('Error guardando selección de BD:', err)
      }
    }
    await loadTables(dbName)
    await loadSchema(dbName)
  }

  // ── TanStack Table ───────────────────────────────────────────────────────
  const table = useReactTable({
    data, columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    globalFilterFn: 'includesString',
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
  })

  // ── Render ───────────────────────────────────────────────────────────────
  const inputClass = 'mt-1 block w-full px-4 py-3 border border-gray-300 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-purple-500 bg-white/80 transition-all duration-300'

  return (
    <div>
      {!isConnected ? (
        /* ── Formulario de conexión ── */
        <div className="bg-white/50 p-8 rounded-2xl shadow-lg border border-white/30">
          <h2 className="text-2xl font-bold mb-6 text-center text-gray-800 flex items-center justify-center gap-2">
            <Link2 size={22} />
            Conectar a Base de Datos
          </h2>

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 text-sm text-blue-700">
            <p className="font-semibold text-blue-800 mb-2">🧪 Base de datos de demo disponible:</p>
            <p><strong>Host:</strong> <code className="text-xs">ep-falling-flower-ai9ck030-pooler.c-4.us-east-1.aws.neon.tech</code></p>
            <p><strong>Puerto:</strong> <code>5432</code> · <strong>BD:</strong> <code>neondb</code></p>
            <p><strong>Solo lectura →</strong> usuario: <code>demo_readonly</code> · contraseña: <code>Demo_Read_2024!</code></p>
            <p><strong>Editor →</strong> usuario: <code>demo_editor</code> · contraseña: <code>Demo_Edit_2024!</code></p>
          </div>

          <form onSubmit={e => { e.preventDefault(); connectToDatabase() }} className="space-y-6">
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-2">Tipo de base de datos</label>
              <ProtectedSelect
                value={dbType}
                onChange={v => setDbType(v as typeof dbType)}
                options={[
                  { value: 'sqlite',   label: 'SQLite' },
                  { value: 'postgres', label: 'PostgreSQL' },
                  { value: 'mysql',    label: 'MySQL' },
                  { value: 'mongodb',  label: 'MongoDB' },
                  { value: 'mssql',    label: 'MSSQL' },
                ]}
                className={inputClass}
              />
            </div>

            {dbType === 'sqlite' ? (
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Ruta del archivo SQLite</label>
                <ProtectedInput placeholder="e.g., ./database.db" type="text" value={sqlitePath} onChange={setSqlitePath} className={inputClass} />
              </div>
            ) : (
              <>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Host / IP</label>
                  <ProtectedInput placeholder="ep-falling-flower-ai9ck030-pooler.c-4.us-east-1.aws.neon.tech" type="text" value={host} onChange={setHost} className={inputClass} />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Puerto</label>
                  <ProtectedInput
                    placeholder={dbType === 'postgres' ? '5432' : dbType === 'mysql' ? '3306' : '27017'}
                    type="text" value={port} onChange={setPort} className={inputClass}
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Base de datos / Schema</label>
                  <ProtectedInput placeholder="neondb" type="text" value={database} onChange={setDatabase} className={inputClass} />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Usuario</label>
                  <ProtectedInput
                    placeholder={dbType === 'postgres' ? 'demo_readonly' : dbType === 'mysql' ? 'root' : 'admin'}
                    type="text" value={username} onChange={setUsername} className={inputClass}
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Contraseña</label>
                  <ProtectedInput placeholder="Contraseña" type="password" value={password} onChange={setPassword} className={inputClass} />
                </div>
              </>
            )}

            <button
              type="submit"
              className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-green-500 to-teal-600 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transition-all duration-200"
            >
              <PlugZap size={18} />
              Conectar
            </button>
          </form>
        </div>

      ) : (
        /* ── Vista conectada ── */
        <div>
          {/* Diagrama ER */}
          <div className="mb-8 bg-white/50 p-6 rounded-2xl shadow-lg border border-white/30">
            <h2 className="text-2xl font-bold mb-4 text-gray-800 flex items-center gap-2">
              <GitFork size={22} />
              Esquema de la BD (Diagrama ER)
            </h2>
            <div style={{ height: 400 }} className="bg-white rounded-xl shadow-inner">
              {nodes.length > 0 ? (
                <ReactFlow
                  nodes={nodes} edges={edges}
                  onNodeClick={(_, node) => { setSelectedTable(node.id); loadTableData(node.id) }}
                >
                  <MiniMap /><Controls /><Background />
                </ReactFlow>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-400">
                  Cargando diagrama...
                </div>
              )}
            </div>
          </div>

          {/* Selección de DB y tabla */}
          <div className="mb-6 bg-white/50 p-6 rounded-2xl shadow-lg border border-white/30">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Base de datos</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1">
                    <ProtectedSelect
                      value={database || ''}
                      onChange={v => handleDatabaseSelect(v)}
                      options={[
                        { value: '', label: database || '(usar por defecto)' },
                        ...(databases || []).map(db => ({ value: db, label: db })),
                      ]}
                      disabled={!isConnected || loadingDbs}
                      className="block w-full px-4 py-3 border border-gray-300 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white/80 transition-all duration-300"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => fetchDatabases()}
                    disabled={loadingDbs}
                    title="Refrescar lista de bases de datos"
                    className="p-3 rounded-xl border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-50 transition-colors"
                  >
                    <RefreshCw size={16} className={loadingDbs ? 'animate-spin' : ''} />
                  </button>
                </div>
                {dbsError && <p className="text-xs text-red-500 mt-1">{dbsError}</p>}
              </div>

              <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Tabla</label>
                <ProtectedSelect
                  value={selectedTable || ''}
                  onChange={v => { setSelectedTable(v); loadTableData(v) }}
                  options={[{ value: '', label: 'Selecciona una tabla' }, ...tables.map(t => ({ value: t, label: t }))]}
                  className="block w-full px-4 py-3 border border-gray-300 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white/80 transition-all duration-300"
                />
              </div>
            </div>
          </div>

          {data.length > 0 && (
            <>
              {/* Exportar */}
              <div className="mb-6 flex items-center justify-between">
                <button
                  onClick={exportData}
                  className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-green-500 to-teal-600 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transition-all duration-200"
                >
                  <Download size={16} />
                  Exportar a CSV
                </button>
              </div>

              {/* Tabla */}
              <div className="bg-white/50 p-6 rounded-2xl shadow-lg border border-white/30">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-2xl font-bold text-gray-800 flex items-center gap-2">
                    <Table2 size={22} />
                    Datos de la tabla
                  </h2>
                  <button
                    onClick={() => setSidebarOpen(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transition-all duration-200"
                  >
                    <BookMarked size={16} />
                    Conexiones guardadas
                  </button>
                </div>
                <TableFilters
                  table={table}
                  globalFilter={globalFilter}
                  setGlobalFilter={setGlobalFilter}
                  data={data}
                  onExportCSV={exportData}
                />
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-gray-200 bg-white rounded-xl overflow-hidden shadow-inner">
                    <thead className="bg-gradient-to-r from-purple-500 to-pink-500 text-white">
                      {table.getHeaderGroups().map(hg => (
                        <tr key={hg.id}>
                          {hg.headers.map(h => (
                            <th key={h.id} className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-wider">
                              {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                            </th>
                          ))}
                        </tr>
                      ))}
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-100">
                      {table.getRowModel().rows.map(row => (
                        <tr key={row.id} className="hover:bg-purple-50 transition-colors duration-150">
                          {row.getVisibleCells().map(cell => (
                            <td key={cell.id} className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {flexRender(cell.column.columnDef.cell, cell.getContext())}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Gráfico */}
              <div className="mt-8 bg-white/50 p-6 rounded-2xl shadow-lg border border-white/30">
                <h2 className="text-2xl font-bold mb-4 text-gray-800 flex items-center gap-2">
                  <BarChart2 size={22} />
                  Gráfico
                </h2>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e7ff" />
                    <XAxis dataKey="name" stroke="#7c3aed" />
                    <YAxis stroke="#7c3aed" />
                    <Tooltip contentStyle={{ backgroundColor: '#f3f4f6', border: 'none', borderRadius: '8px' }} />
                    <Legend />
                    <Bar dataKey="value" fill="url(#dbColorGradient)" />
                    <defs>
                      <linearGradient id="dbColorGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#8b5cf6" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#ec4899" stopOpacity={0.8} />
                      </linearGradient>
                    </defs>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </>
          )}
        </div>
      )}

      {/* Sidebar de conexiones guardadas */}
      <DatabaseSidebar
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        currentConnection={currentSavedConnection}
        onConnectionSelect={async (connection: SavedConnection) => {
          setDbType(connection.dbType)
          if (connection.dbType === 'sqlite') {
            setSqlitePath(connection.connectionString || '')
            setHost(''); setPort(''); setDatabase(''); setUsername(''); setPassword('')
          } else {
            setHost(connection.config?.host || '')
            setPort(connection.config?.port?.toString() || '')
            setDatabase(connection.config?.database || '')
            setUsername(connection.config?.user || '')
            setPassword(connection.config?.password || '')
            setSqlitePath('')
          }
          await connectToDatabase()
          setCurrentSavedConnection(connection)
          setSidebarOpen(false)
        }}
        onSaveCurrentConnection={async (name: string) => {
          const payload: Record<string, unknown> = { name, dbType }
          if (dbType === 'sqlite') payload.connectionString = sqlitePath
          else if (dbType === 'mysql') payload.config = { host, port: parseInt(port) || 3306, user: username, password, database }
          else payload.connectionString = `${dbType}://${username}:${password}@${host}:${port}/${database}`

          const res = await fetch('/api/db/connections', {
            method: 'POST', headers: authHeaders, body: JSON.stringify(payload),
          })
          if (!res.ok) { const e = await res.json(); throw new Error(e.error || 'Error guardando') }
          const json = await res.json()
          setCurrentSavedConnection(json.connection)
          await fetchSavedConnections()
          alert('Conexión guardada')
        }}
        token={token}
      />
    </div>
  )
}
