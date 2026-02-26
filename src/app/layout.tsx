/**
 * Layout Raíz de Next.js - layout.tsx
 *
 * Este archivo define el layout raíz de la aplicación Next.js.
 * Se aplica a todas las páginas y proporciona la estructura HTML base,
 * metadatos SEO, estilos globales y configuración común.
 *
 * Características:
 * - Metadatos SEO optimizados para motores de búsqueda
 * - Idioma español configurado
 * - Favicon personalizado
 * - Estilos globales aplicados
 * - Estructura HTML5 semántica
 *
 * @author José Ángel Alejo
 * @version 1.1.0
 */
import type { Metadata } from "next";
import { SpeedInsights } from "@vercel/speed-insights/next";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";
import '@xyflow/react/dist/style.css';

/**
 * Metadatos SEO para la aplicación
 * Configurados para optimización en motores de búsqueda
 */
export const metadata: Metadata = {
  title: "Data Visualizer",
  description: "Visualiza datos de JSON/CSV y bases de datos con diagramas ER",
};

/**
 * Componente RootLayout - Layout principal de Next.js
 *
 * Proporciona la estructura HTML base para toda la aplicación.
 * Next.js automáticamente envuelve todas las páginas con este layout.
 *
 * @param children Contenido de la página actual (componentes hijos)
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es">
      <head>
        {/* Favicon personalizado de la aplicación */}
        <link rel="icon" href="/05_logo_icon_256x256.png" />
      </head>
      <body className="font-sans antialiased">
        {/* Renderizado del contenido de la página actual */}
        {children}
        {/* Vercel Speed Insights para monitoreo de rendimiento */}
        <SpeedInsights />
        {/* Vercel Analytics para seguimiento de visitas */}
        <Analytics />
      </body>
    </html>
  );
}