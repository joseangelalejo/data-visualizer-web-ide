'use client'

/**
 * LoginForm — Formulario de inicio de sesión.
 * Extraído de page.tsx para mantener el componente principal limpio.
 */

import React, { useState } from 'react'
import { Eye, EyeOff, LogIn } from 'lucide-react'
import ProtectedInput from './ProtectedInput'

interface LoginFormProps {
  onSuccess: (token: string) => void
  onSwitchToRegister: () => void
}

export default function LoginForm({ onSuccess, onSwitchToRegister }: LoginFormProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (res.ok) {
        const data = await res.json()
        onSuccess(data.token)
      } else {
        const err = await res.json()
        setError(err.error || 'Credenciales incorrectas')
      }
    } catch {
      setError('Error de conexión. Inténtalo de nuevo.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Usuario</label>
        <ProtectedInput
          placeholder="Tu nombre de usuario"
          type="text"
          value={username}
          onChange={setUsername}
          className="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
          required
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Contraseña</label>
        <div className="flex items-center gap-2">
          <ProtectedInput
            placeholder="Tu contraseña"
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={setPassword}
            className="flex-1 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            required
          />
          <button
            type="button"
            onClick={() => setShowPassword(s => !s)}
            className="p-2 border border-gray-300 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-50 transition-colors"
            aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
          >
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
      </div>

      {error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
          {error}
        </p>
      )}

      {/* Credenciales de prueba */}
      <div className="bg-indigo-50 border border-indigo-200 rounded-md px-3 py-2 text-sm text-indigo-700 text-center">
        <span className="font-medium">Demo:</span> usuario <code className="font-mono bg-indigo-100 px-1 rounded">user1</code> · contraseña <code className="font-mono bg-indigo-100 px-1 rounded">user123</code>
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-indigo-500 to-purple-600 text-white py-2 px-4 rounded-md hover:shadow-lg transition-all duration-200 disabled:opacity-60 disabled:cursor-not-allowed"
      >
        <LogIn size={16} />
        {loading ? 'Entrando...' : 'Iniciar sesión'}
      </button>

      <p className="text-center text-sm text-gray-600">
        ¿No tienes cuenta?{' '}
        <button
          type="button"
          onClick={onSwitchToRegister}
          className="text-indigo-600 hover:underline font-medium"
        >
          Crear una cuenta
        </button>
      </p>
    </form>
  )
}