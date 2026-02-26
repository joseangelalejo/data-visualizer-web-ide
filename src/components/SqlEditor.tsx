'use client'

/**
 * SqlEditor — Editor SQL completo estilo SQLTools.
 *
 * Funcionalidades:
 * - Monaco Editor con resaltado SQL, autocompletado y formato
 * - Múltiples pestañas de scripts
 * - Conexión propia independiente a cualquier BD soportada
 * - Ejecución de query completa o selección parcial (Ctrl+Enter)
 * - Resultados en tabla con exportación CSV/JSON
 * - Historial de queries (últimas 50, guardado en localStorage)
 * - Scripts guardados en localStorage (nunca en servidor)
 * - Indicador de tiempo de ejecución y conteo de filas
 * - Explorador de esquema en sidebar
 *
 * @author José Ángel Alejo
 * @version 1.1.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Play, Plus, X, Save, FolderOpen, Clock, Database, ChevronRight,
  ChevronDown, Download, Copy, Trash2, PlugZap, PlugZapIcon,
  RefreshCw, Table2, AlertCircle, CheckCircle2, Columns,
  WrapText, History, FileCode2, Link2Off,
} from 'lucide-react'
import ProtectedSelect from './ProtectedSelect'
import ProtectedInput from './ProtectedInput'

// ── Tipos ────────────────────────────────────────────────────────────────────

type DbType = 'sqlite' | 'postgres' | 'mysql' | 'mongodb' | 'mssql'

interface EditorTab {
  id: string
  title: string
  content: string
  isDirty: boolean   // tiene cambios sin guardar
}

interface QueryResult {
  columns: string[]
  rows: Record<string, unknown>[]
  rowCount: number
  executionMs: number
  query: string
  error?: string
  timestamp: Date
}

interface HistoryEntry {
  id: string
  query: string
  executionMs: number
  rowCount: number
  error?: string
  timestamp: string  // ISO string para localStorage
}

interface SavedScript {
  id: string
  name: string
  content: string
  createdAt: string
}

interface SchemaTable {
  name: string
  columns: { name: string; type: string }[]
  expanded: boolean
}

interface EditorConnection {
  dbType: DbType
  connectionString: string
  config: {
    host: string
    port: string
    database: string
    user: string
    password: string
  }
}

// ── Constantes localStorage ───────────────────────────────────────────────────
const LS_HISTORY = 'sqleditor_history'
const LS_SCRIPTS = 'sqleditor_scripts'
const LS_TABS = 'sqleditor_tabs'
const LS_CONN = 'sqleditor_connection'
const MAX_HISTORY = 50

// ── Helpers localStorage ──────────────────────────────────────────────────────
function lsGet<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch { return fallback }
}
function lsSet(key: string, value: unknown) {
  try { localStorage.setItem(key, JSON.stringify(value)) } catch { /* cuota llena */ }
}

// ── Componente principal ─────────────────────────────────────────────────────
export default function SqlEditor({ token }: { token: string }) {
  // ── Estado de conexión ───────────────────────────────────────────────────
  const [isConnected, setIsConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [connError, setConnError] = useState('')
  const [conn, setConn] = useState<EditorConnection>(() => lsGet(LS_CONN, {
    dbType: 'sqlite',
    connectionString: '',
    config: { host: 'localhost', port: '5432', database: '', user: '', password: '' },
  }))

  // ── Estado de pestañas ───────────────────────────────────────────────────
  const [tabs, setTabs] = useState<EditorTab[]>(() => {
    const saved = lsGet<EditorTab[]>(LS_TABS, [])
    return saved.length > 0 ? saved : [{ id: uid(), title: 'Script 1', content: '-- Escribe tu query aquí\nSELECT 1;', isDirty: false }]
  })
  const [activeTabId, setActiveTabId] = useState<string>(() => {
    const saved = lsGet<EditorTab[]>(LS_TABS, [])
    return saved.length > 0 ? saved[0].id : tabs[0]?.id || ''
  })

  // ── Estado de ejecución ──────────────────────────────────────────────────
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<QueryResult | null>(null)
  const [resultPage, setResultPage] = useState(0)
  const ROWS_PER_PAGE = 50

  // ── Estado de UI lateral ─────────────────────────────────────────────────
  const [sidePanel, setSidePanel] = useState<'schema' | 'history' | 'scripts' | null>('schema')
  const [schema, setSchema] = useState<SchemaTable[]>([])
  const [loadingSchema, setLoadingSchema] = useState(false)
  const [loadingDatabases, setLoadingDatabases] = useState(false)
  const [databases, setDatabases] = useState<string[]>([])
  const [history, setHistory] = useState<HistoryEntry[]>(() => lsGet(LS_HISTORY, []))
  const [scripts, setScripts] = useState<SavedScript[]>(() => lsGet(LS_SCRIPTS, []))
  const [saveScriptName, setSaveScriptName] = useState('')
  const [showSaveDialog, setShowSaveDialog] = useState(false)

  // ── Monaco ───────────────────────────────────────────────────────────────
  const monacoContainerRef = useRef<HTMLDivElement>(null)
  const monacoEditorRef = useRef<any>(null)   // monaco.editor.IStandaloneCodeEditor
  const monacoRef = useRef<any>(null)         // monaco namespace
  const [monacoReady, setMonacoReady] = useState(false)
  const [monacoError, setMonacoError] = useState<string | null>(null)
  const [reloadMonacoKey, setReloadMonacoKey] = useState(0)

  // ── Persistir tabs en localStorage ──────────────────────────────────────
  useEffect(() => { lsSet(LS_TABS, tabs) }, [tabs])
  useEffect(() => { lsSet(LS_CONN, conn) }, [conn])

  // Auto-cargar lista de bases cuando el usuario introduce host/creds o cambia el tipo
  useEffect(() => {
    let t: any = null
    if (conn.dbType !== 'sqlite' && (conn.connectionString || (conn.config.host && conn.config.user))) {
      t = setTimeout(() => { loadDatabases() }, 400)
    } else {
      setDatabases([])
    }
    return () => { if (t) clearTimeout(t) }
  }, [conn.dbType, conn.connectionString, conn.config.host, conn.config.user])

  // ── Registrar autocompletado en Monaco ───────────────────────────────────
  const registerCompletions = useCallback((schemaData: SchemaTable[]) => {
    const monaco = monacoRef.current
    if (!monaco) return

    // Limpiar el proveedor anterior si existe
    if ((window as any).__sqlCompletionDisposable) {
      try { (window as any).__sqlCompletionDisposable.dispose() } catch { }
    }

    const keywords = [
      'SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN',
      'ON', 'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT INTO',
      'VALUES', 'UPDATE', 'SET', 'DELETE FROM', 'CREATE TABLE', 'DROP TABLE',
      'ALTER TABLE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'IS NULL', 'IS NOT NULL',
      'DISTINCT', 'AS', 'UNION', 'UNION ALL', 'WITH', 'CASE', 'WHEN', 'THEN',
      'ELSE', 'END', 'USE', 'SHOW', 'DESCRIBE', 'EXPLAIN', 'COUNT', 'SUM',
      'AVG', 'MIN', 'MAX', 'COALESCE', 'NULLIF', 'CAST', 'CONVERT',
    ]

    const disposable = monaco.languages.registerCompletionItemProvider('sql', {
      triggerCharacters: [' ', '.', '\n'],
      provideCompletionItems: (model: any, position: any) => {
        const word = model.getWordUntilPosition(position)
        const range = {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: word.startColumn,
          endColumn: word.endColumn,
        }

        const suggestions: any[] = []

        // Keywords SQL
        keywords.forEach(kw => {
          suggestions.push({
            label: kw,
            kind: monaco.languages.CompletionItemKind.Keyword,
            insertText: kw,
            range,
            sortText: '3' + kw,
          })
        })

        // Tablas
        schemaData.forEach(table => {
          suggestions.push({
            label: table.name,
            kind: monaco.languages.CompletionItemKind.Class,
            insertText: table.name,
            detail: `Tabla (${table.columns.length} columnas)`,
            documentation: table.columns.map(c => `${c.name}: ${c.type}`).join('\n'),
            range,
            sortText: '1' + table.name,
          })

          // Columnas de cada tabla
          table.columns.forEach(col => {
            suggestions.push({
              label: col.name,
              kind: monaco.languages.CompletionItemKind.Field,
              insertText: col.name,
              detail: `${table.name}.${col.name} (${col.type})`,
              range,
              sortText: '2' + col.name,
            })
          })
        })

        return { suggestions }
      },
    })

      ; (window as any).__sqlCompletionDisposable = disposable
  }, [])

  // ── Cargar Monaco desde CDN ───────────────────────────────────────────────
  useEffect(() => {
    if (typeof window === 'undefined') return
    if ((window as any).monaco) { initMonaco((window as any).monaco); return }

    // Intentar primero import local (empaquetado). Si falla, usar CDNs secuenciales.
    (async () => {
      try {
        // Import ESM del API — esto incluirá Monaco en el bundle si está instalado
        const monacoModule = await import('monaco-editor/esm/vs/editor/editor.api')
        const monacoLocal = (monacoModule as any).default ?? monacoModule
        initMonaco(monacoLocal)
        setMonacoError(null)
        return
      } catch (err) {
        // no está instalado o falló la carga por bundling — seguimos con CDNs
      }

      // CDN candidates (en este orden): Cloudflare, jsDelivr, unpkg
      const version = '0.44.0'
      const cdns = [
        { script: `https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/${version}/min/vs/loader.min.js`, vs: `https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/${version}/min/vs` },
        { script: `https://cdn.jsdelivr.net/npm/monaco-editor@${version}/min/vs/loader.min.js`, vs: `https://cdn.jsdelivr.net/npm/monaco-editor@${version}/min/vs` },
        { script: `https://unpkg.com/monaco-editor@${version}/min/vs/loader.min.js`, vs: `https://unpkg.com/monaco-editor@${version}/min/vs` },
      ]

      let aborted = false
      const TIMEOUT_MS = 6000

      const cleanupScript = (s: HTMLScriptElement | null) => { if (!s) return; try { s.remove() } catch { } }

      const tryLoad = (i: number) => {
        if (aborted) return
        if (i >= cdns.length) {
          setMonacoError('No se pudo cargar Monaco desde ningún CDN — usando editor de texto.')
          return
        }
        const { script: scriptUrl, vs: vsPath } = cdns[i]

        // si ya existe un loader con el mismo src, quitamos para forzar reintento
        document.querySelectorAll('script[data-monaco-loader]').forEach(s => s.remove())

        const s = document.createElement('script')
        s.src = scriptUrl
        s.setAttribute('data-monaco-loader', `attempt-${i}`)
        let timedOut = false
        const to = setTimeout(() => { timedOut = true; cleanupScript(s); if (!(window as any).monaco) tryLoad(i + 1) }, TIMEOUT_MS)

        s.onload = () => {
          clearTimeout(to)
          if (timedOut) return // ya expiró
          try {
            const require = (window as any).require
            if (!require) {
              // loader no expuso `require` — intentar siguiente CDN
              cleanupScript(s)
              tryLoad(i + 1)
              return
            }
            require.config({ paths: { vs: vsPath } })
            require(['vs/editor/editor.main'], (monaco: any) => {
              if (!monaco) {
                cleanupScript(s)
                tryLoad(i + 1)
                return
              }
              initMonaco(monaco)
              setMonacoError(null)
            })
          } catch (err) {
            // fallar silenciosamente al siguiente CDN
            cleanupScript(s)
            tryLoad(i + 1)
          }
        }

        s.onerror = () => {
          clearTimeout(to)
          cleanupScript(s)
          tryLoad(i + 1)
        }

        document.head.appendChild(s)
      }

      tryLoad(0)

      return () => { aborted = true }
    })()
  }, [reloadMonacoKey])

  const initMonaco = (monaco: any) => {
    try {
      monacoRef.current = monaco
      if (!monacoContainerRef.current) return

      // dispose previous editor if any (reintentos)
      if ((monacoEditorRef.current as any)?.dispose) {
        try { (monacoEditorRef.current as any).dispose() } catch { /* ignore */ }
        // limpiar listeners debug previos (si existen)
        try {
          const prevDebug = (monacoEditorRef.current as any).__debugDisposables
          if (Array.isArray(prevDebug)) prevDebug.forEach((d: any) => { try { d.dispose() } catch { } })
        } catch { }
        monacoEditorRef.current = null
      }

      const editor = monaco.editor.create(monacoContainerRef.current, {
        value: activeTab?.content || '',
        language: 'sql',
        theme: 'vs',
        fontSize: 14,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, monospace",
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        wordWrap: 'on',
        lineNumbers: 'on',
        renderLineHighlight: 'all',
        suggestOnTriggerCharacters: true,
        quickSuggestions: true,
        automaticLayout: true,
        padding: { top: 12, bottom: 12 },
      })

      // Asegurar que el editor está en modo editable y recibir foco
      try { editor.updateOptions({ readOnly: false, accessibilitySupport: 'on' }) } catch { }
      try { editor.focus() } catch { }
      // Forzar pointer-events por si hay CSS hostil
      try { const node = editor.getDomNode && editor.getDomNode(); if (node) node.style.pointerEvents = 'auto' } catch { }

      // --- Comandos básicos ---
      // Ctrl+Enter → ejecutar
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => runQuery())
      // Ctrl+Shift+F → formatear
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyF, () => formatSQL())

      // Undo / Redo explicit bindings (ensure they work even if outer handlers exist)
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyZ, () => { try { (editor as any).getAction('undo').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyY, () => { try { (editor as any).getAction('redo').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyZ, () => { try { (editor as any).getAction('redo').run() } catch { } }) } catch { }

      // Common editing shortcuts
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Slash, () => { try { (editor as any).getAction('editor.action.commentLine').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyD, () => { try { (editor as any).getAction('editor.action.addSelectionToNextFindMatch').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.F2, () => { try { (editor as any).getAction('editor.action.rename').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyC), () => { try { (editor as any).getAction('editor.action.commentLine').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyU), () => { try { (editor as any).getAction('editor.action.removeCommentLine').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyX), () => { try { (editor as any).getAction('editor.action.trimTrailingWhitespace').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyL, () => { try { (editor as any).getAction('editor.action.selectHighlights').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.Digit0), () => { try { (editor as any).getAction('editor.foldAll').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyJ), () => { try { (editor as any).getAction('editor.unfoldAll').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyI), () => { try { (editor as any).getAction('editor.action.showHover').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.Alt | monaco.KeyCode.UpArrow, () => { try { (editor as any).getAction('editor.action.moveLinesUpAction').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.Alt | monaco.KeyCode.DownArrow, () => { try { (editor as any).getAction('editor.action.moveLinesDownAction').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyL, () => { try { (editor as any).getAction('editor.action.selectLines').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyK, () => { try { (editor as any).getAction('editor.action.deleteLines').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyF, () => { try { (editor as any).getAction('actions.find').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyH, () => { try { (editor as any).getAction('editor.action.startFindReplaceAction').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyG, () => { try { (editor as any).getAction('editor.action.gotoLine').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyA, () => { try { (editor as any).getAction('editor.action.blockComment').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.Shift | monaco.KeyMod.Alt | monaco.KeyCode.KeyF, () => { try { (editor as any).getAction('editor.action.formatDocument').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.chord(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyK, monaco.KeyCode.KeyF), () => { try { (editor as any).getAction('editor.action.formatSelection').run() } catch { } }) } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Space, () => { try { (editor as any).getAction('editor.action.triggerSuggest').run() } catch { } }) } catch { }
      // Acción explícita para asegurar que Ctrl/Cmd+Space dispara el autocompletado
      try {
        editor.addAction({
          id: 'sqleditor.triggerSuggest',
          label: 'Trigger suggestion (Ctrl/Cmd+Space)',
          keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.Space],
          run: () => { try { (editor as any).getAction('editor.action.triggerSuggest').run() } catch { } }
        })
      } catch { }
      try { editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyP, () => { try { (editor as any).getAction('editor.action.quickCommand').run() } catch { } }) } catch { }

      // Guardar contenido al escribir
      editor.onDidChangeModelContent(() => {
        const value = editor.getValue()
        setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, content: value, isDirty: true } : t))
      })

      // --- Instrumentación de teclado/ratón ---
      const debugDisposables: any[] = []

      try {
        const dSel = editor.onDidChangeCursorSelection((_e: any) => {
          try { editor.focus && editor.focus() } catch { }
        })
        debugDisposables.push(dSel)
      } catch { }

      const docKeyHandler = (ev: KeyboardEvent) => {
        try {
          if (!editor || !(editor as any).hasTextFocus || !(editor as any).hasTextFocus()) return

          const key = ev.key
          const arrowKeys = ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight']
          if (arrowKeys.includes(key)) {
            if (ev.ctrlKey || ev.metaKey || ev.altKey) return

            try {
              ev.preventDefault(); ev.stopPropagation()

              if (key === 'ArrowUp' || key === 'ArrowDown') {
                const cmd = key === 'ArrowUp' ? 'cursorUp' : 'cursorDown'
                  ; (editor as any).trigger('keyboard', cmd, { select: ev.shiftKey })
                return
              }

              if (key === 'ArrowLeft' || key === 'ArrowRight') {
                const isLeft = key === 'ArrowLeft'
                const cmd = isLeft ? (ev.shiftKey ? 'cursorLeftSelect' : 'cursorLeft') : (ev.shiftKey ? 'cursorRightSelect' : 'cursorRight')
                  ; (editor as any).trigger('keyboard', cmd, {})
                return
              }
            } catch (err) {
              try {
                const p = (editor as any).getPosition()
                const model = (editor as any).getModel()
                if (!p || !model) return
                let newLine = p.lineNumber + (key === 'ArrowUp' ? -1 : key === 'ArrowDown' ? 1 : 0)
                newLine = Math.max(1, Math.min(model.getLineCount(), newLine))
                const maxCol: number = model.getLineMaxColumn(newLine);
                const newCol: number = (p.column < maxCol ? p.column : maxCol) as number;
                (editor as any).setPosition({ lineNumber: newLine, column: newCol });
                if (ev.shiftKey) {
                  const prevSel: any = (editor as any).getSelection();
                  const startLineNumber: number = prevSel?.startLineNumber ?? 1;
                  const startColumn: number = prevSel?.startColumn ?? 1;
                  (editor as any).setSelection({ startLineNumber, startColumn, endLineNumber: newLine, endColumn: newCol });
                }
              } catch { /* ignore */ }
            }
          }
        } catch { /* swallow */ }
      }
      document.addEventListener('keydown', docKeyHandler, true)
      debugDisposables.push({ dispose: () => document.removeEventListener('keydown', docKeyHandler, true) })

      const mousedownHandler = (_ev: MouseEvent) => { /* overlay detection placeholder */ }
      try { monacoContainerRef.current?.addEventListener('mousedown', mousedownHandler, true); debugDisposables.push({ dispose: () => monacoContainerRef.current?.removeEventListener('mousedown', mousedownHandler, true) }) } catch { }

      const mousemoveHandler = (ev: MouseEvent) => {
        try { lastMouse.current = { x: ev.clientX, y: ev.clientY } } catch { }
      }
      try { monacoContainerRef.current?.addEventListener('mousemove', mousemoveHandler, true); debugDisposables.push({ dispose: () => monacoContainerRef.current?.removeEventListener('mousemove', mousemoveHandler, true) }) } catch { }

      const mouseupHandler = (_ev: MouseEvent) => {
        try {
          const ed = monacoEditorRef.current as any
          if (!ed) return
          try {
            const sel = (ed as any).getSelection && (ed as any).getSelection()
            if (sel && !(sel.startLineNumber === sel.endLineNumber && sel.startColumn === sel.endColumn)) {
              try { ed.focus && ed.focus() } catch { }
            }
          } catch { }
        } catch { }
      }
      try { monacoContainerRef.current?.addEventListener('mouseup', mouseupHandler, true); debugDisposables.push({ dispose: () => monacoContainerRef.current?.removeEventListener('mouseup', mouseupHandler, true) }) } catch { }

      ; (editor as any).__debugDisposables = debugDisposables

      monacoEditorRef.current = editor
      try { (window as any).monaco = monaco } catch { }

      // ── Registrar autocompletado con el esquema actual (si ya está cargado) ──
      if (schema.length > 0) {
        registerCompletions(schema)
      }

      setMonacoError(null)
      setMonacoReady(true)
    } catch (err) {
      console.error('initMonaco error', err)
      setMonacoError(String(err || 'Error inicializando Monaco'))
      setMonacoReady(false)
    }
  }

  // Sincronizar contenido del editor cuando cambia la pestaña activa
  useEffect(() => {
    const editor = monacoEditorRef.current as any
    if (!editor || !monacoReady) return
    const tab = tabs.find(t => t.id === activeTabId)
    if (tab && editor.getValue() !== tab.content) {
      editor.setValue(tab.content)
    }
    try { editor.focus && editor.focus() } catch { }
  }, [activeTabId, monacoReady])

  // ── Obtener pestaña activa ────────────────────────────────────────────────
  const activeTab = tabs.find(t => t.id === activeTabId) || tabs[0]

  // ── Conexión ─────────────────────────────────────────────────────────────
  const buildPayload = useCallback((c: EditorConnection) => {
    if (c.dbType === 'sqlite') return { dbType: c.dbType, connectionString: c.connectionString }
    if (c.dbType === 'mysql') return {
      dbType: c.dbType,
      config: { host: c.config.host, port: parseInt(c.config.port) || 3306, user: c.config.user, password: c.config.password, database: c.config.database },
    }
    return {
      dbType: c.dbType,
      connectionString: `${c.dbType}://${c.config.user}:${c.config.password}@${c.config.host}:${c.config.port}/${c.config.database}?sslmode=require`,
    }
  }, [])

  const connect = async () => {
    setConnecting(true)
    setConnError('')
    try {
      const res = await fetch('/api/db/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(buildPayload(conn)),
      })
      if (res.ok) {
        setIsConnected(true)
        await loadDatabases()
        await loadSchema()
      } else {
        const err = await res.json()
        setConnError(err.error || 'Error de conexión')
      }
    } catch (e) {
      setConnError('Error de red. Comprueba la conexión.')
    } finally {
      setConnecting(false)
    }
  }

  const disconnect = () => {
    setIsConnected(false)
    setSchema([])
    setResult(null)
    // Limpiar completions al desconectar
    if ((window as any).__sqlCompletionDisposable) {
      try { (window as any).__sqlCompletionDisposable.dispose() } catch { }
      delete (window as any).__sqlCompletionDisposable
    }
  }

  // ── Cargar esquema ───────────────────────────────────────────────────────
  const loadSchema = async () => {
    setLoadingSchema(true)
    try {
      const res = await fetch('/api/db/schema', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(buildPayload(conn)),
      })
      if (res.ok) {
        const json = await res.json()
        const schemaData = (json.schema || []).map((t: any) => ({ ...t, expanded: false }))
        setSchema(schemaData)
        registerCompletions(schemaData) // ← Registrar autocompletado con el nuevo esquema
      }
    } catch { /* silencioso */ }
    finally { setLoadingSchema(false) }
  }

  const loadDatabases = async () => {
    if (!conn || conn.dbType === 'sqlite') { setDatabases([]); return }
    setLoadingDatabases(true)
    try {
      const res = await fetch('/api/db/databases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(buildPayload(conn)),
      })
      if (res.ok) {
        const json = await res.json()
        setDatabases((json.databases || []).map((d: any) => String(d.name)).filter((n: string) => {
          const lower = n.toLowerCase()
          return !['information_schema', 'mysql', 'performance_schema', 'sys'].includes(lower)
        }))
      }
    } catch (err) {
      // silencioso
    } finally {
      setLoadingDatabases(false)
    }
  }

  // ── Ejecutar query ───────────────────────────────────────────────────────
  const runQuery = useCallback(async () => {
    if (!isConnected || running) return

    const editor = monacoEditorRef.current as any
    let queryToRun = ''

    if (editor) {
      const selection = editor.getSelection()
      const selectedText = editor.getModel()?.getValueInRange(selection)
      queryToRun = selectedText?.trim() || editor.getValue().trim()
    } else {
      queryToRun = activeTab?.content?.trim() || ''
    }

    if (!queryToRun) return

    setRunning(true)
    setResultPage(0)
    const start = Date.now()

    try {
      const res = await fetch('/api/db/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ...buildPayload(conn), query: queryToRun }),
      })
      const json = await res.json()
      const ms = Date.now() - start

      const useRegex = /USE\s+([`']?)([\w\-\.]+)\1/gi
      let lastUse: RegExpExecArray | null = null
      while (true) {
        const m = useRegex.exec(queryToRun)
        if (!m) break
        lastUse = m
      }
      if (lastUse && res.ok) {
        const selectedDb = lastUse[2]
        setConn(c => ({ ...c, config: { ...c.config, database: selectedDb } }))
        setTimeout(() => { loadSchema(); loadDatabases() }, 50)
      }

      if (!res.ok) {
        const errResult: QueryResult = {
          columns: [], rows: [], rowCount: 0,
          executionMs: ms, query: queryToRun,
          error: json.error || 'Error desconocido',
          timestamp: new Date(),
        }
        setResult(errResult)
        addToHistory(queryToRun, ms, 0, json.error)
      } else {
        const rows: Record<string, unknown>[] = json.data || []
        const cols = rows.length > 0 ? Object.keys(rows[0]) : []
        const qResult: QueryResult = {
          columns: cols, rows, rowCount: rows.length,
          executionMs: ms, query: queryToRun,
          timestamp: new Date(),
        }
        setResult(qResult)
        addToHistory(queryToRun, ms, rows.length)
      }
    } catch (e) {
      const ms = Date.now() - start
      setResult({ columns: [], rows: [], rowCount: 0, executionMs: ms, query: queryToRun, error: 'Error de red', timestamp: new Date() })
      addToHistory(queryToRun, ms, 0, 'Error de red')
    } finally {
      setRunning(false)
    }
  }, [isConnected, running, conn, activeTab, token, buildPayload])

  // ── Historial ────────────────────────────────────────────────────────────
  const addToHistory = (query: string, ms: number, rows: number, error?: string) => {
    const entry: HistoryEntry = { id: uid(), query, executionMs: ms, rowCount: rows, error, timestamp: new Date().toISOString() }
    setHistory(prev => {
      const next = [entry, ...prev].slice(0, MAX_HISTORY)
      lsSet(LS_HISTORY, next)
      return next
    })
  }

  const loadFromHistory = (entry: HistoryEntry) => {
    setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, content: entry.query, isDirty: true } : t))
    const editor = monacoEditorRef.current as any
    if (editor) {
      editor.setValue(entry.query)
      try { editor.focus() } catch { }
    }
  }

  // ── Scripts guardados (localStorage) ────────────────────────────────────
  const saveScript = () => {
    if (!saveScriptName.trim()) return
    const tab = tabs.find(t => t.id === activeTabId)
    const content = (monacoEditorRef.current as any)?.getValue() || tab?.content || ''
    const script: SavedScript = { id: uid(), name: saveScriptName.trim(), content, createdAt: new Date().toISOString() }
    setScripts(prev => {
      const next = [script, ...prev]
      lsSet(LS_SCRIPTS, next)
      return next
    })
    setSaveScriptName('')
    setShowSaveDialog(false)
    setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, title: script.name, isDirty: false } : t))
  }

  const loadScript = (script: SavedScript) => {
    const newTab: EditorTab = { id: uid(), title: script.name, content: script.content, isDirty: false }
    setTabs(prev => [...prev, newTab])
    setActiveTabId(newTab.id)
    setTimeout(() => { try { (monacoEditorRef.current as any)?.focus() } catch { } }, 50)
  }

  const deleteScript = (id: string) => {
    setScripts(prev => {
      const next = prev.filter(s => s.id !== id)
      lsSet(LS_SCRIPTS, next)
      return next
    })
  }

  const exportScript = (script: SavedScript) => {
    const blob = new Blob([script.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `${script.name}.sql`; a.click()
    URL.revokeObjectURL(url)
  }

  // ── Pestañas ─────────────────────────────────────────────────────────────
  const addTab = () => {
    const n = tabs.length + 1
    const tab: EditorTab = { id: uid(), title: `Script ${n}`, content: '', isDirty: false }
    setTabs(prev => [...prev, tab])
    setActiveTabId(tab.id)
  }

  const closeTab = (id: string) => {
    if (tabs.length === 1) return
    const idx = tabs.findIndex(t => t.id === id)
    const next = tabs.filter(t => t.id !== id)
    setTabs(next)
    if (activeTabId === id) setActiveTabId(next[Math.max(0, idx - 1)]?.id || '')
  }

  const renameTab = (id: string, name: string) => {
    setTabs(prev => prev.map(t => t.id === id ? { ...t, title: name } : t))
  }

  // ── Formato SQL ──────────────────────────────────────────────────────────
  const formatSQL = () => {
    const editor = monacoEditorRef.current as any
    if (!editor) return
    const raw = editor.getValue()
    const keywords = ['SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'ON',
      'GROUP BY', 'ORDER BY', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT INTO', 'VALUES', 'UPDATE', 'SET',
      'DELETE FROM', 'CREATE TABLE', 'DROP TABLE', 'ALTER TABLE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'IS NULL',
      'IS NOT NULL', 'DISTINCT', 'AS', 'UNION', 'UNION ALL', 'WITH', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END']
    let formatted = raw
    keywords.forEach(kw => {
      formatted = formatted.replace(new RegExp(`\\b${kw}\\b`, 'gi'), kw)
    })
      ;['SELECT', 'FROM', 'WHERE', 'JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'INNER JOIN', 'GROUP BY', 'ORDER BY',
        'HAVING', 'LIMIT', 'UNION', 'WITH'].forEach(kw => {
          formatted = formatted.replace(new RegExp(`\\s+${kw}\\b`, 'g'), `\n${kw}`)
        })
    formatted = formatted.trim()
    editor.setValue(formatted)
  }

  // ── Exportar resultados ──────────────────────────────────────────────────
  const exportResults = (format: 'csv' | 'json') => {
    if (!result || result.rows.length === 0) return
    let content = ''
    let mime = ''
    let ext = ''
    if (format === 'csv') {
      content = [result.columns.join(','), ...result.rows.map(r => result.columns.map(c => `"${String(r[c] ?? '').replace(/"/g, '""')}"`).join(','))].join('\n')
      mime = 'text/csv'; ext = 'csv'
    } else {
      content = JSON.stringify(result.rows, null, 2)
      mime = 'application/json'; ext = 'json'
    }
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `resultado.${ext}`; a.click()
    URL.revokeObjectURL(url)
  }

  // ── Copiar query al portapapeles ─────────────────────────────────────────
  const copyQuery = () => {
    const editor = monacoEditorRef.current as any
    const q = editor?.getValue() || activeTab?.content || ''
    navigator.clipboard.writeText(q).catch(() => { })
  }

  // ── Toggle columna del esquema ────────────────────────────────────────────
  const toggleTable = (name: string) => {
    setSchema(prev => prev.map(t => t.name === name ? { ...t, expanded: !t.expanded } : t))
  }

  // ── Insertar nombre de tabla en editor ────────────────────────────────────
  const insertIntoEditor = (text: string) => {
    const editor = monacoEditorRef.current as any
    if (!editor) return
    const pos = editor.getPosition()
    editor.executeEdits('', [{ range: { startLineNumber: pos.lineNumber, startColumn: pos.column, endLineNumber: pos.lineNumber, endColumn: pos.column }, text: `${text} ` }])
    editor.focus()
  }

  // Helper: get statements with offsets for client-side selection
  function getStatementsWithOffsets(sql: string) {
    const stmts: { start: number; end: number; text: string }[] = []
    let inSingle = false
    let inDouble = false
    let inBacktick = false
    let inLineComment = false
    let inBlockComment = false
    let stmtStart = 0

    for (let i = 0; i < sql.length; i++) {
      const ch = sql[i]
      const next = sql[i + 1]

      if (inLineComment) {
        if (ch === '\n') { inLineComment = false }
        continue
      }
      if (inBlockComment) {
        if (ch === '*' && next === '/') { inBlockComment = false; i++ }
        continue
      }

      if (!inSingle && !inDouble && !inBacktick && ch === '-' && next === '-') { inLineComment = true; i++; continue }
      if (!inSingle && !inDouble && !inBacktick && ch === '/' && next === '*') { inBlockComment = true; i++; continue }

      if (ch === "'" && !inDouble && !inBacktick) { inSingle = !inSingle; continue }
      if (ch === '"' && !inSingle && !inBacktick) { inDouble = !inDouble; continue }
      if (ch === '`' && !inSingle && !inDouble) { inBacktick = !inBacktick; continue }

      if (ch === ';' && !inSingle && !inDouble && !inBacktick && !inLineComment && !inBlockComment) {
        const text = sql.slice(stmtStart, i).trim()
        if (text) stmts.push({ start: stmtStart, end: i, text })
        stmtStart = i + 1
      }
    }
    const last = sql.slice(stmtStart).trim()
    if (last) {
      const start = stmtStart
      const end = sql.length
      stmts.push({ start, end, text: last })
    }
    return stmts
  }

  function findStatementAtOffset(sql: string, offset: number) {
    const stmts = getStatementsWithOffsets(sql)
    for (const s of stmts) {
      if (offset >= s.start && offset <= s.end) return s
    }
    return null
  }

  const executeQueryString = async (queryToRun: string) => {
    if (!isConnected || running) return
    if (!queryToRun || !queryToRun.trim()) return
    setRunning(true)
    setResultPage(0)
    const start = Date.now()
    try {
      const res = await fetch('/api/db/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ...buildPayload(conn), query: queryToRun }),
      })
      const json = await res.json()
      const ms = Date.now() - start

      const useRegex = /USE\s+([`']?)([\w\-\.]+)\1/gi
      let lastUse: RegExpExecArray | null = null
      while (true) {
        const m = useRegex.exec(queryToRun)
        if (!m) break
        lastUse = m
      }
      if (lastUse && res.ok) {
        const selectedDb = lastUse[2]
        setConn(c => ({ ...c, config: { ...c.config, database: selectedDb } }))
        setTimeout(() => { loadSchema(); loadDatabases() }, 50)
      }

      if (!res.ok) {
        const errResult: QueryResult = { columns: [], rows: [], rowCount: 0, executionMs: ms, query: queryToRun, error: json.error || 'Error desconocido', timestamp: new Date() }
        setResult(errResult)
        addToHistory(queryToRun, ms, 0, json.error)
      } else {
        const rows: Record<string, unknown>[] = json.data || []
        const cols = rows.length > 0 ? Object.keys(rows[0]) : []
        const qResult: QueryResult = { columns: cols, rows, rowCount: rows.length, executionMs: ms, query: queryToRun, timestamp: new Date() }
        setResult(qResult)
        addToHistory(queryToRun, ms, rows.length)
      }
    } catch (e) {
      const ms = Date.now() - start
      setResult({ columns: [], rows: [], rowCount: 0, executionMs: ms, query: queryToRun, error: 'Error de red', timestamp: new Date() })
      addToHistory(queryToRun, ms, 0, 'Error de red')
    } finally {
      setRunning(false)
    }
  }

  const runSelection = async () => {
    const editor: any = monacoEditorRef.current
    if (editor) {
      const selection = editor.getSelection()
      const selectedText = editor.getModel()?.getValueInRange(selection)?.trim()
      if (selectedText) return executeQueryString(selectedText)

      const pos = editor.getPosition()
      const model = editor.getModel()
      const offset = model.getOffsetAt(pos)
      const sql = model.getValue()
      const stmt = findStatementAtOffset(sql, offset)
      if (stmt) {
        const startPos = model.getPositionAt(stmt.start)
        const endPos = model.getPositionAt(stmt.end)
        editor.setSelection({ startLineNumber: startPos.lineNumber, startColumn: startPos.column, endLineNumber: endPos.lineNumber, endColumn: endPos.column })
        editor.focus()
        return executeQueryString(stmt.text)
      }
    } else {
      const ta = monacoContainerRef.current?.querySelector('textarea') as HTMLTextAreaElement | null
      if (!ta) return
      const val = ta.value
      const selStart = ta.selectionStart
      const stmt = findStatementAtOffset(val, selStart)
      if (stmt) {
        const txt = val.slice(stmt.start, stmt.end).trim()
        return executeQueryString(txt)
      }
      if (ta.selectionEnd > ta.selectionStart) {
        const txt = val.slice(ta.selectionStart, ta.selectionEnd).trim()
        return executeQueryString(txt)
      }
    }
  }

  const lastMouse = useRef<{ x: number; y: number } | null>(null)
  const selectStatementUnderMouse = () => {
    const editor: any = monacoEditorRef.current
    const rect = monacoContainerRef.current?.getBoundingClientRect()
    const lm = lastMouse.current
    if (!editor || !rect || !lm) return
    try {
      const target = (editor.getTargetAtClientPoint && editor.getTargetAtClientPoint(lm.x, lm.y)) || null
      const pos = target?.position || editor.getPosition()
      const model = editor.getModel()
      const offset = model.getOffsetAt(pos)
      const sql = model.getValue()
      const stmt = findStatementAtOffset(sql, offset)
      if (stmt) {
        const startPos = model.getPositionAt(stmt.start)
        const endPos = model.getPositionAt(stmt.end)
        editor.setSelection({ startLineNumber: startPos.lineNumber, startColumn: startPos.column, endLineNumber: endPos.lineNumber, endColumn: endPos.column })
        editor.focus()
      }
    } catch { /* ignore */ }
  }

  // ── Paginación de resultados ─────────────────────────────────────────────
  const pagedRows = result ? result.rows.slice(resultPage * ROWS_PER_PAGE, (resultPage + 1) * ROWS_PER_PAGE) : []
  const totalPages = result ? Math.ceil(result.rows.length / ROWS_PER_PAGE) : 0

  // ── Inputs de conexión ───────────────────────────────────────────────────
  const inputCls = 'block w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-purple-500 bg-white'
  const defaultPort: Record<DbType, string> = { sqlite: '', postgres: '5432', mysql: '3306', mongodb: '27017', mssql: '1433' }

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full" style={{ minHeight: '80vh' }}>

      {/* ── Barra de conexión ─────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-4 mb-4">
        {!isConnected ? (
          <div>
            <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
              <Link2Off size={15} className="text-gray-400" />
              Configurar conexión del editor SQL
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              {/* Tipo de BD */}
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Tipo</label>
                <ProtectedSelect
                  value={conn.dbType}
                  onChange={v => {
                    const d = v as DbType
                    setConn(c => ({ ...c, dbType: d, config: { ...c.config, port: defaultPort[d] } }))
                  }}
                  options={[
                    { value: 'sqlite', label: 'SQLite' },
                    { value: 'postgres', label: 'PostgreSQL' },
                    { value: 'mysql', label: 'MySQL' },
                    { value: 'mongodb', label: 'MongoDB' },
                    { value: 'mssql', label: 'MSSQL' },
                  ]}
                  className="border border-gray-300 rounded-lg text-sm"
                />
              </div>

              {conn.dbType === 'sqlite' ? (
                <div className="md:col-span-3">
                  <label className="block text-xs font-medium text-gray-600 mb-1">Ruta del archivo</label>
                  <ProtectedInput
                    type="text" placeholder="./database.db"
                    value={conn.connectionString}
                    onChange={v => setConn(c => ({ ...c, connectionString: v }))}
                    className={inputCls}
                  />
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Host</label>
                    <ProtectedInput type="text" placeholder="ep-falling-flower-ai9ck030-pooler.c-4.us-east-1.aws.neon.tech" value={conn.config.host}
                      onChange={v => setConn(c => ({ ...c, config: { ...c.config, host: v } }))} className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Puerto</label>
                    <ProtectedInput type="text" placeholder={defaultPort[conn.dbType]} value={conn.config.port}
                      onChange={v => setConn(c => ({ ...c, config: { ...c.config, port: v } }))} className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Base de datos</label>
                    <ProtectedInput type="text" placeholder="neondb" value={conn.config.database}
                      onChange={v => setConn(c => ({ ...c, config: { ...c.config, database: v } }))} className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Usuario</label>
                    <ProtectedInput type="text" placeholder="demo_readonly" value={conn.config.user}
                      onChange={v => setConn(c => ({ ...c, config: { ...c.config, user: v } }))} className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Contraseña</label>
                    <ProtectedInput type="password" placeholder="••••••••" value={conn.config.password}
                      onChange={v => setConn(c => ({ ...c, config: { ...c.config, password: v } }))} className={inputCls} />
                  </div>
                </>
              )}
            </div>

            {connError && (
              <div className="mt-3 flex items-center gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                <AlertCircle size={14} /> {connError}
              </div>
            )}

            <button
              onClick={connect} disabled={connecting}
              className="mt-4 flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-green-500 to-teal-600 text-white text-sm font-semibold rounded-xl shadow hover:shadow-md transition-all disabled:opacity-60"
            >
              <PlugZap size={15} />
              {connecting ? 'Conectando...' : 'Conectar'}
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} className="text-green-500" />
              <span className="text-sm font-medium text-gray-700">
                Conectado a <span className="font-bold text-purple-700">{conn.dbType.toUpperCase()}</span>
                {conn.dbType !== 'sqlite' && conn.config.database && (
                  <> · <span className="text-gray-500">{conn.config.database}</span></>
                )}
                {conn.dbType === 'sqlite' && (
                  <> · <span className="text-gray-500 font-mono text-xs">{conn.connectionString}</span></>
                )}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => loadSchema()} title="Refrescar esquema"
                className="p-1.5 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-500 transition-colors">
                <RefreshCw size={14} className={loadingSchema ? 'animate-spin' : ''} />
              </button>
              <button onClick={disconnect}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50 transition-colors">
                <PlugZapIcon size={14} /> Desconectar
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Área principal (sidebar + editor + resultados) ─────────────────── */}
      <div className="flex gap-4 flex-1" style={{ minHeight: 0 }}>

        {/* ── Sidebar izquierdo ─────────────────────────────────────────── */}
        <div className="w-64 flex-shrink-0 flex flex-col gap-2">
          <div className="flex gap-1 bg-white border border-gray-200 rounded-xl p-1">
            {([
              { id: 'schema', icon: <Database size={14} />, label: 'Esquema' },
              { id: 'history', icon: <History size={14} />, label: 'Historial' },
              { id: 'scripts', icon: <FileCode2 size={14} />, label: 'Scripts' },
            ] as const).map(btn => (
              <button key={btn.id}
                onClick={() => setSidePanel(p => p === btn.id ? null : btn.id)}
                className={`flex-1 flex items-center justify-center gap-1 py-1.5 rounded-lg text-xs font-medium transition-all ${sidePanel === btn.id ? 'bg-purple-100 text-purple-700' : 'text-gray-500 hover:bg-gray-50'}`}
              >
                {btn.icon} {btn.label}
              </button>
            ))}
          </div>

          <div className="flex-1 bg-white border border-gray-200 rounded-xl overflow-hidden flex flex-col" style={{ maxHeight: '60vh' }}>
            {/* Esquema */}
            {sidePanel === 'schema' && (
              <div className="flex flex-col h-full">
                {conn.dbType !== 'sqlite' && (isConnected || conn.connectionString || conn.config.host || conn.config.user) && (
                  <div className="px-3 py-2 border-b border-gray-100 flex items-center gap-2">
                    <div className="flex-1">
                      <label className="block text-xs font-medium text-gray-500 mb-1">Bases de datos</label>
                      <ProtectedSelect
                        value={conn.config.database || ''}
                        onChange={v => {
                          const dbName = String(v || '')
                          setConn(c => ({ ...c, config: { ...c.config, database: dbName } }))
                          setTimeout(() => { loadSchema() }, 20)
                        }}
                        options={[{ value: '', label: '<Selecciona una base>' }, ...databases.map(d => ({ value: d, label: d }))]}
                        className="w-full text-sm"
                      />
                    </div>
                    <div className="flex items-end gap-2">
                      <button onClick={loadDatabases} title="Refrescar bases" className="p-1.5 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-500 transition-colors">
                        <RefreshCw size={14} className={loadingDatabases ? 'animate-spin' : ''} />
                      </button>
                    </div>
                  </div>
                )}

                <div className="px-3 py-2 border-b border-gray-100 flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-600">Tablas ({schema.length})</span>
                  {isConnected && (
                    <button onClick={loadSchema} className="text-gray-400 hover:text-purple-600 transition-colors">
                      <RefreshCw size={12} className={loadingSchema ? 'animate-spin' : ''} />
                    </button>
                  )}
                </div>

                <div className="overflow-y-auto flex-1">
                  {!isConnected ? (
                    <p className="text-xs text-gray-400 p-3 text-center">Conecta una BD para ver el esquema</p>
                  ) : loadingSchema ? (
                    <p className="text-xs text-gray-400 p-3 text-center">Cargando...</p>
                  ) : schema.length === 0 ? (
                    <p className="text-xs text-gray-400 p-3 text-center">No se encontraron tablas</p>
                  ) : schema.map(table => (
                    <div key={table.name}>
                      <button
                        onClick={() => toggleTable(table.name)}
                        onDoubleClick={() => insertIntoEditor(table.name)}
                        className="w-full flex items-center gap-1.5 px-3 py-2 hover:bg-purple-50 transition-colors text-left group"
                        title="Doble clic para insertar en editor"
                      >
                        {table.expanded ? <ChevronDown size={12} className="text-gray-400" /> : <ChevronRight size={12} className="text-gray-400" />}
                        <Table2 size={12} className="text-purple-500 flex-shrink-0" />
                        <span className="text-xs text-gray-700 truncate font-medium">{table.name}</span>
                        <span className="ml-auto text-xs text-gray-400 hidden group-hover:block">{table.columns.length}</span>
                      </button>
                      {table.expanded && (
                        <div className="ml-6 border-l border-gray-100">
                          {table.columns.map(col => (
                            <button
                              key={col.name}
                              onClick={() => insertIntoEditor(col.name)}
                              className="w-full flex items-center gap-1.5 px-3 py-1 hover:bg-blue-50 transition-colors text-left"
                              title="Clic para insertar en editor"
                            >
                              <Columns size={10} className="text-blue-400 flex-shrink-0" />
                              <span className="text-xs text-gray-600 truncate">{col.name}</span>
                              <span className="ml-auto text-xs text-gray-400 truncate">{col.type}</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Historial */}
            {sidePanel === 'history' && (
              <div className="flex flex-col h-full">
                <div className="px-3 py-2 border-b border-gray-100 flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-600">Últimas {history.length} queries</span>
                  <button onClick={() => { setHistory([]); lsSet(LS_HISTORY, []) }} className="text-gray-400 hover:text-red-500 transition-colors" title="Limpiar historial">
                    <Trash2 size={12} />
                  </button>
                </div>
                <div className="overflow-y-auto flex-1">
                  {history.length === 0 ? (
                    <p className="text-xs text-gray-400 p-3 text-center">Sin historial todavía</p>
                  ) : history.map(entry => (
                    <button key={entry.id} onClick={() => loadFromHistory(entry)}
                      className="w-full text-left px-3 py-2 border-b border-gray-50 hover:bg-gray-50 transition-colors group"
                    >
                      <div className="flex items-center gap-1 mb-1">
                        {entry.error
                          ? <AlertCircle size={10} className="text-red-400 flex-shrink-0" />
                          : <CheckCircle2 size={10} className="text-green-400 flex-shrink-0" />
                        }
                        <span className="text-xs text-gray-400">{entry.executionMs}ms · {entry.rowCount} filas</span>
                        <span className="ml-auto text-xs text-gray-300">{new Date(entry.timestamp).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-xs text-gray-600 font-mono truncate">{entry.query}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Scripts guardados */}
            {sidePanel === 'scripts' && (
              <div className="flex flex-col h-full">
                <div className="px-3 py-2 border-b border-gray-100">
                  <span className="text-xs font-semibold text-gray-600">Scripts guardados ({scripts.length})</span>
                  <p className="text-xs text-gray-400 mt-0.5">Guardados en este dispositivo</p>
                </div>
                <div className="overflow-y-auto flex-1">
                  {scripts.length === 0 ? (
                    <p className="text-xs text-gray-400 p-3 text-center">Usa el botón Guardar para salvar scripts</p>
                  ) : scripts.map(script => (
                    <div key={script.id} className="px-3 py-2 border-b border-gray-50 hover:bg-gray-50 group">
                      <div className="flex items-center justify-between">
                        <button onClick={() => loadScript(script)} className="text-xs font-medium text-gray-700 hover:text-purple-600 truncate text-left flex-1">
                          {script.name}
                        </button>
                        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button onClick={() => exportScript(script)} title="Descargar .sql" className="p-1 text-gray-400 hover:text-blue-500">
                            <Download size={11} />
                          </button>
                          <button onClick={() => deleteScript(script.id)} title="Eliminar" className="p-1 text-gray-400 hover:text-red-500">
                            <Trash2 size={11} />
                          </button>
                        </div>
                      </div>
                      <p className="text-xs text-gray-400 mt-0.5 font-mono truncate">{script.content.split('\n')[0]}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {sidePanel === null && (
              <div className="flex items-center justify-center h-full text-gray-300">
                <Database size={32} />
              </div>
            )}
          </div>
        </div>

        {/* ── Área central (pestañas + editor + resultados) ──────────────── */}
        <div className="flex-1 flex flex-col min-w-0">

          {/* Pestañas */}
          <div className="flex items-center gap-0 border-b border-gray-200 bg-white rounded-t-xl overflow-x-auto">
            {tabs.map(tab => (
              <div key={tab.id}
                className={`flex items-center gap-1.5 px-3 py-2 border-r border-gray-100 cursor-pointer min-w-0 flex-shrink-0 group transition-colors ${activeTabId === tab.id ? 'bg-purple-50 border-b-2 border-b-purple-500' : 'hover:bg-gray-50'}`}
                onClick={() => setActiveTabId(tab.id)}
              >
                <FileCode2 size={12} className={activeTabId === tab.id ? 'text-purple-500' : 'text-gray-400'} />
                <span
                  className={`text-xs font-medium max-w-24 truncate ${activeTabId === tab.id ? 'text-purple-700' : 'text-gray-600'}`}
                  onDoubleClick={e => {
                    const el = e.currentTarget
                    el.contentEditable = 'true'
                    el.focus()
                    const onBlur = () => { renameTab(tab.id, el.textContent || tab.title); el.contentEditable = 'false' }
                    el.addEventListener('blur', onBlur, { once: true })
                    el.addEventListener('keydown', (ev: KeyboardEvent) => { if (ev.key === 'Enter') { ev.preventDefault(); el.blur() } }, { once: true })
                  }}
                  title="Doble clic para renombrar"
                >
                  {tab.isDirty ? `${tab.title} ●` : tab.title}
                </span>
                {tabs.length > 1 && (
                  <button onClick={e => { e.stopPropagation(); closeTab(tab.id) }}
                    className="opacity-0 group-hover:opacity-100 text-gray-400 hover:text-red-500 transition-all ml-0.5">
                    <X size={11} />
                  </button>
                )}
              </div>
            ))}
            <button onClick={addTab} className="px-3 py-2 text-gray-400 hover:text-purple-600 hover:bg-gray-50 transition-colors flex-shrink-0" title="Nueva pestaña">
              <Plus size={14} />
            </button>
          </div>

          {/* Toolbar del editor */}
          <div className="flex items-center gap-2 px-3 py-2 bg-white border-x border-gray-200 flex-wrap">
            <button
              onClick={runQuery} disabled={!isConnected || running}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-green-500 to-teal-500 text-white text-xs font-semibold rounded-lg shadow-sm hover:shadow disabled:opacity-50 transition-all"
            >
              <Play size={12} />
              {running ? 'Ejecutando...' : 'Ejecutar'}
              <kbd className="ml-1 text-xs opacity-70 bg-white/20 px-1 rounded">⌘↵</kbd>
            </button>

            <button
              onClick={runSelection} disabled={!isConnected || running}
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
              title="Ejecutar selección (o sentencia actual si no hay selección)"
            >
              Ejecutar selección
            </button>

            <button
              onClick={selectStatementUnderMouse}
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors"
              title="Seleccionar sentencia bajo el ratón"
            >
              Seleccionar sentencia
            </button>

            <div className="h-4 w-px bg-gray-200" />

            <button onClick={formatSQL} title="Formatear SQL (⌘⇧F)"
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
              <WrapText size={12} /> Formatear
            </button>

            <button onClick={copyQuery} title="Copiar query"
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
              <Copy size={12} /> Copiar
            </button>

            <button onClick={() => setShowSaveDialog(true)} title="Guardar script en local"
              className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
              <Save size={12} /> Guardar
            </button>

            <div className="h-4 w-px bg-gray-200" />

            <label className="flex items-center gap-1 px-2 py-1.5 text-xs text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors cursor-pointer" title="Cargar .sql desde disco">
              <FolderOpen size={12} /> Abrir .sql
              <input type="file" accept=".sql,.txt" className="hidden" onChange={e => {
                const file = e.target.files?.[0]
                if (!file) return
                const reader = new FileReader()
                reader.onload = ev => {
                  const content = ev.target?.result as string
                  setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, content, isDirty: true, title: file.name.replace('.sql', '') } : t));
                  (monacoEditorRef.current as any)?.setValue(content)
                }
                reader.readAsText(file)
                e.target.value = ''
              }} />
            </label>

            {!isConnected && (
              <span className="ml-auto text-xs text-amber-600 bg-amber-50 border border-amber-200 px-2 py-1 rounded-lg flex items-center gap-1">
                <AlertCircle size={11} /> Sin conexión
              </span>
            )}
          </div>

          {/* Monaco Editor */}
          <div
            ref={monacoContainerRef}
            className="border-x border-gray-200 bg-white"
            style={{ height: '280px', pointerEvents: 'auto' }}
            onClick={(ev) => {
              const ed = monacoEditorRef.current as any
              try {
                if (ed?.focus) {
                  try { ed.focus() } catch { }
                  try {
                    const sel = (ed as any).getSelection && (ed as any).getSelection()
                    if (sel && !(sel.startLineNumber === sel.endLineNumber && sel.startColumn === sel.endColumn)) {
                      return
                    }
                  } catch { /* ignore */ }

                  const clickedInsideMonaco = (ev.target as HTMLElement)?.closest?.('.monaco-editor')
                  if (clickedInsideMonaco) return

                  try {
                    const target = (ed.getTargetAtClientPoint && ed.getTargetAtClientPoint(ev.clientX, ev.clientY)) || null
                    if (target && target.position) {
                      try { ed.setPosition(target.position); ed.revealPositionInCenterIfOutsideViewport && ed.revealPositionInCenterIfOutsideViewport(target.position) } catch { }
                    }
                  } catch { }
                } else {
                  const ta = monacoContainerRef.current?.querySelector('textarea') as HTMLTextAreaElement | null
                  if (ta) try { ta.focus() } catch { }
                }
              } catch { /* swallow */ }
            }}
          >
            {monacoReady && !monacoError ? null : monacoError ? (
              <div className="flex flex-col h-full p-3 gap-3">
                <div className="flex items-center justify-between bg-amber-50 border border-amber-100 rounded px-3 py-2 text-sm text-amber-700">
                  <div className="flex items-center gap-2">
                    <AlertCircle size={14} />
                    <span>Editor Monaco no disponible — usando editor de texto.</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => { setMonacoError(null); setReloadMonacoKey(k => k + 1); }}
                      className="text-xs px-2 py-1 bg-white border rounded hover:bg-gray-50"
                    >
                      Reintentar
                    </button>
                  </div>
                </div>

                <textarea
                  value={(monacoEditorRef.current as any)?.getValue?.() || activeTab?.content || ''}
                  onChange={e => {
                    const v = e.target.value
                    setTabs(prev => prev.map(t => t.id === activeTabId ? { ...t, content: v, isDirty: true } : t))
                  }}
                  onKeyDown={e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runQuery() } }}
                  className="w-full h-full resize-none p-3 border border-gray-200 rounded-lg font-mono text-sm bg-white text-gray-800"
                />
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-400 text-sm gap-2">
                <RefreshCw size={16} className="animate-spin" /> Cargando editor...
              </div>
            )}
          </div>

          {/* Diálogo guardar script */}
          {showSaveDialog && (
            <div className="border-x border-gray-200 bg-yellow-50 px-4 py-3 flex items-center gap-3">
              <Save size={14} className="text-yellow-600 flex-shrink-0" />
              <span className="text-xs text-yellow-700 font-medium">Nombre del script:</span>
              <input
                type="text" value={saveScriptName} onChange={e => setSaveScriptName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') saveScript(); if (e.key === 'Escape') setShowSaveDialog(false) }}
                placeholder="Mi query..."
                className="flex-1 px-2 py-1 text-sm border border-yellow-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-yellow-400 bg-white text-gray-800"
                autoFocus
              />
              <button onClick={saveScript} disabled={!saveScriptName.trim()}
                className="px-3 py-1 bg-yellow-500 text-white text-xs rounded-lg hover:bg-yellow-600 disabled:opacity-50 transition-colors">
                Guardar
              </button>
              <button onClick={() => setShowSaveDialog(false)} className="text-gray-400 hover:text-gray-600">
                <X size={14} />
              </button>
            </div>
          )}

          {/* Panel de resultados */}
          <div className="flex-1 border border-gray-200 rounded-b-xl bg-white overflow-hidden flex flex-col" style={{ minHeight: '200px', maxHeight: '40vh' }}>
            {!result ? (
              <div className="flex flex-col items-center justify-center h-full text-gray-400 gap-2">
                <Play size={28} className="opacity-30" />
                <span className="text-sm">Ejecuta una query para ver los resultados</span>
                <span className="text-xs opacity-60">Atajo: Ctrl+Enter (o ⌘+Enter en Mac)</span>
              </div>
            ) : result.error ? (
              <div className="p-4">
                <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-xl p-4">
                  <AlertCircle size={16} className="text-red-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-semibold text-red-700">Error al ejecutar la query</p>
                    <p className="text-sm text-red-600 font-mono mt-1">{result.error}</p>
                    <p className="text-xs text-red-400 mt-2">{result.executionMs}ms · {result.timestamp.toLocaleTimeString()}</p>
                  </div>
                </div>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between px-4 py-2 border-b border-gray-100 bg-gray-50 flex-wrap gap-2">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1 text-xs text-green-600 font-medium">
                      <CheckCircle2 size={12} /> {result.rowCount} fila{result.rowCount !== 1 ? 's' : ''}
                    </span>
                    <span className="flex items-center gap-1 text-xs text-gray-500">
                      <Clock size={12} /> {result.executionMs}ms
                    </span>
                    {totalPages > 1 && (
                      <span className="text-xs text-gray-400">
                        Página {resultPage + 1} de {totalPages}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {totalPages > 1 && (
                      <>
                        <button disabled={resultPage === 0} onClick={() => setResultPage(p => p - 1)}
                          className="px-2 py-0.5 text-xs border border-gray-200 rounded hover:bg-gray-100 disabled:opacity-40 transition-colors">← Ant</button>
                        <button disabled={resultPage >= totalPages - 1} onClick={() => setResultPage(p => p + 1)}
                          className="px-2 py-0.5 text-xs border border-gray-200 rounded hover:bg-gray-100 disabled:opacity-40 transition-colors">Sig →</button>
                      </>
                    )}
                    <button onClick={() => exportResults('csv')}
                      className="flex items-center gap-1 px-2 py-1 text-xs border border-gray-200 rounded-lg text-gray-600 hover:bg-gray-50 transition-colors">
                      <Download size={11} /> CSV
                    </button>
                    <button onClick={() => exportResults('json')}
                      className="flex items-center gap-1 px-2 py-1 text-xs border border-gray-200 rounded-lg text-gray-600 hover:bg-gray-50 transition-colors">
                      <Download size={11} /> JSON
                    </button>
                  </div>
                </div>

                <div className="overflow-auto flex-1">
                  <table className="min-w-full text-xs">
                    <thead className="sticky top-0 bg-gradient-to-r from-purple-500 to-pink-500 text-white">
                      <tr>
                        <th className="px-3 py-2 text-left font-semibold text-gray-400 w-10 select-none">#</th>
                        {result.columns.map(col => (
                          <th key={col} className="px-3 py-2 text-left font-semibold uppercase tracking-wider whitespace-nowrap">{col}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {pagedRows.map((row, i) => (
                        <tr key={i} className="hover:bg-purple-50 transition-colors">
                          <td className="px-3 py-1.5 text-gray-400 select-none">{resultPage * ROWS_PER_PAGE + i + 1}</td>
                          {result.columns.map(col => (
                            <td key={col} className="px-3 py-1.5 text-gray-800 whitespace-nowrap font-mono max-w-48 truncate" title={String(row[col] ?? '')}>
                              {row[col] === null || row[col] === undefined
                                ? <span className="text-gray-300 italic">NULL</span>
                                : String(row[col])}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>

        </div>
      </div>
    </div>
  )
}

// ── Utilidad ──────────────────────────────────────────────────────────────────
function uid() {
  return Math.random().toString(36).slice(2, 10)
}