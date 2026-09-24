# Frontend Navigation & Black Screen Glitch Fix Documentation

## Autonomous SOC Analyst Platform

---

### 1. Executive Summary & Problem Analysis

During normal sidebar navigation across SOC modules (such as **Detections**, **Logs**, **Evidence Timeline**, **Detection Analytics**, and **Pipeline Trace**), the application would intermittently freeze or turn into a completely blank, dark screen (`#090d16`) before rendering or failing to recover.

This was not a simple network latency issue or minor timeout bug. A thorough architectural investigation uncovered **six distinct, interrelated root causes** spanning React error bubbling, component layout unmounting, missing CSS utility classes, Axios interceptor side-effects, and unhandled array/object properties.

---

### 2. Identified Root Causes

#### Root Cause 1: Total Unmounting of `#root` Due to Missing Error Boundaries (Critical)
* **Mechanism**: In React 18, if any component throws an uncaught JavaScript runtime error (such as a `TypeError` when reading properties of `null` or `undefined`) during rendering, React's default behavior is to **unmount the entire component tree** up to the nearest Error Boundary.
* **Failure Mode**: There was **zero** `ErrorBoundary` component in the entire application. When an unhandled error occurred, React tore down `#root` completely, leaving only the bare HTML document.
* **Visual Effect**: In `index.html`, the body element is styled with `class="bg-[#090d16]"`. With `#root` completely emptied, the entire browser window became a blank pitch-black canvas with no error message, no sidebar, and no recovery mechanism.

#### Root Cause 2: Unsafe Data Access in Shared Components (`DataTable.tsx`)
* **Mechanism**: In `DataTable.tsx`, `data` was accepted as a prop and queried directly:
  ```tsx
  // Vulnerable pattern:
  data.length === 0 ? (...) : (data.map(...))
  ```
* **Failure Mode**: If any page passed `null` or `undefined` (common when an API endpoint returned `{ data: null }`, an error occurred, or an API call was still resolving), calling `data.length` or `data.map` threw:
  `TypeError: Cannot read properties of undefined (reading 'length')` or `reading 'map'`.
* **Impact**: Affected 9 core modules including **Detections**, **Logs**, **Alerts**, **Incidents**, **Risk Analysis**, and **Sigma Rules**.

#### Root Cause 3: Undefined Tailwind Utility Classes Creating "Black Visual Voids"
* **Mechanism**: Three newly added modules (`DetectionAnalytics.tsx`, `EvidenceTimeline.tsx`, and `PipelineTrace.tsx`) made extensive use of classes such as `bg-dark-800`, `bg-dark-900`, `border-dark-700`, and `border-dark-600`.
* **Failure Mode**: In `tailwind.config.js`, no `dark` color palette was defined—only `soc: { ... }` and standard Tailwind palettes. Consequently, Tailwind generated **no CSS rules** for these utility classes.
* **Visual Effect**: Elements styled with `bg-dark-800` rendered with `background-color: transparent`. Against the dark `#090d16` application background, large panels, KPI cards, timeline nodes, and tables appeared as empty black voids, mimicking a crashed screen.

#### Root Cause 4: Destructive Hard Page Reloads on Axios 401 Interceptors (`api.ts`)
* **Mechanism**: `api.interceptors.response.use` had an un-debounced status handler:
  ```ts
  if (error.response?.status === 401) {
    localStorage.removeItem("asoc_access_token");
    window.location.href = "/login";
  }
  ```
* **Failure Mode**: When multiple requests fired concurrently during rapid navigation or background polling, any transient 401 triggered `window.location.href = "/login"`. This executed a **full browser reload**, discarding the in-memory React application and displaying a black screen while re-fetching bundles and re-authenticating.

#### Root Cause 5: Request Storming in `Navbar.tsx` on Route Changes
* **Mechanism**: In `Navbar.tsx`, a `useEffect` hook tracked `[location.pathname]`:
  ```tsx
  useEffect(() => {
    fetchStatus(); // Parallel calls to /notifications/unread-count and /health
  }, [location.pathname]);
  ```
* **Failure Mode**: Every time the user clicked a sidebar link, `Navbar` canceled previous timers and immediately fired two background HTTP GET requests. Combined with the new page's own 3–5 initial data requests, rapid clicks flooded the browser connection pool, causing request starvation and rendering delays.

#### Root Cause 6: Unhandled Properties in New SOC Module Pages
* **`EvidenceTimeline.tsx`**: Called `e.stage.toUpperCase()`, `e.severity.toLowerCase()`, and `e.description.toLowerCase()` inside `filter()` without checking if `e.stage`, `e.severity`, or `e.description` were defined.
* **`PipelineTrace.tsx`**: Did `const items = res.data?.data?.items || res.data?.data || []` followed by `items.map()`. When an endpoint returned an object instead of an array, `items.map` threw `items.map is not a function`.
* **`DetectionAnalytics.tsx`**: Queried `data.daily_trend.length`, `data.top_rules.slice()`, and `data.detections_by_endpoint.map()` without array guards.
* **`Dashboard.tsx`**: Used `data?.recent_alerts.map(...)` without an array fallback.
* **`AlertManagement.tsx`**: Used `aiAnalysis.recommended_actions.map(...)` without optional chaining.
* **`IncidentDetail.tsx`**: Used `incident.alerts.map(...)` and `aiAdvice.recommended_actions.map(...)` without array fallback guards.
* **`AICopilot.tsx`**: Used `analysis.recommended_actions.map(...)` without checking existence.
* **`SOCHealth.tsx`**: Rendered no skeleton when loading without report data, leaving an empty void.

---

### 3. Architecture & Code Changes Implemented

#### 1. Created Enterprise SOC React Error Boundary (`ErrorBoundary.tsx`)
* **Location**: `frontend/src/components/common/ErrorBoundary.tsx`
* **Features**:
  * Implements `getDerivedStateFromError` and `componentDidCatch`.
  * Logs component faults with timestamp and component stack trace.
  * Renders a dedicated SOC Error Card: *"Unable to Render [Module Name]"*.
  * Action Buttons: **"Retry Loading"** (clears error state) and **"Return to Dashboard"** (safe navigation).
  * Collapsible **"Technical Diagnostics & Stack Trace"** accordion displaying the exact error message and stack trace.

#### 2. Persistent Layout Shell (`AppLayout.tsx`)
* **Location**: `frontend/src/layouts/AppLayout.tsx`
* **Changes**:
  * The persistent shell (`Sidebar` and `Navbar`) is permanently mounted.
  * `<Outlet />` is wrapped inside `<ErrorBoundary moduleName="SOC Module">` and `<Suspense fallback={<ModuleLoadingSkeleton />}>`.
  * **Result**: Even if a page encounters an error or is loading data, the Sidebar and Navbar **never** unmount or disappear. The user can always click another module or return to the dashboard.

#### 3. Top-Level Safety Guard (`App.tsx`)
* **Location**: `frontend/src/App.tsx`
* **Changes**: Wrapped the entire `<Routes>` tree inside an outer `<ErrorBoundary moduleName="Autonomous SOC Platform">` to guarantee that catastrophic top-level faults never expose the blank HTML body.

#### 4. Hardened Shared `DataTable.tsx`
* **Location**: `frontend/src/components/common/DataTable.tsx`
* **Changes**:
  * Defaulted props: `columns = []`, `data = []`.
  * Safe array coercions: `const safeColumns = Array.isArray(columns) ? columns : []; const safeData = Array.isArray(data) ? data : [];`.
  * Safe empty checks: `safeData.length === 0`.
  * Wrapped individual table cell rendering in defensive `try/catch` blocks so a single malformed record cannot crash the table.

#### 5. Configured Tailwind Palette & Standardized Styles
* **Location**: `frontend/tailwind.config.js`
* **Changes**:
  * Added `dark` color palette:
    ```js
    dark: {
      600: "#334155",
      700: "#1e293b",
      800: "#0f172a",
      900: "#0b0f19",
      950: "#070a12",
    }
    ```
  * Added `primary` aliases (`400: #22d3ee`, `500: #06b6d4`, `600: #0891b2`).
  * Converted raw `dark-*` classes across `DetectionAnalytics.tsx`, `EvidenceTimeline.tsx`, and `PipelineTrace.tsx` to standardized Tailwind `slate-*` / `soc-*` utilities with explicit borders and backgrounds.

#### 6. Safe Axios 401 Interceptor (`api.ts`)
* **Location**: `frontend/src/services/api.ts`
* **Changes**:
  * Added `isRedirecting` state lock to eliminate redundant reload storms.
  * Excluded `/auth/login` and `/auth/register` endpoints from 401 redirects.
  * Dispatches custom event `asoc:unauthorized` and debounces redirects cleanly.

#### 7. Decoupled Navbar Polling (`Navbar.tsx`)
* **Location**: `frontend/src/components/common/Navbar.tsx`
* **Changes**:
  * Changed `useEffect(..., [location.pathname])` to `useEffect(..., [])`.
  * Status checks (`/notifications/unread-count`, `/health`) now execute once on mount and on a smooth 30-second interval, eliminating request storms during navigation.

#### 8. Defensively Hardened All Pages
* **`DetectionAnalytics.tsx`**: Added nullish guards to `by_severity`, `quality_metrics`, `daily_trend`, `top_rules`, `detections_by_endpoint`, and `top_mitre_techniques`.
* **`EvidenceTimeline.tsx`**: Added optional chaining and empty string defaults to `(e.stage || '').toUpperCase()`, `(e.severity || '').toLowerCase()`, and text matching.
* **`PipelineTrace.tsx`**: Hardened `loadRecentEntities` to verify `Array.isArray` across multiple response envelope structures.
* **`Dashboard.tsx`**: Safely defaulted `(data?.recent_alerts || []).map(...)`.
* **`AlertManagement.tsx`**: Safely defaulted `(aiAnalysis?.recommended_actions || []).map(...)`.
* **`IncidentDetail.tsx`**: Safely defaulted `(incident?.alerts || []).map(...)` and `(aiAdvice?.recommended_actions || []).map(...)`.
* **`AICopilot.tsx`**: Safely defaulted `(analysis.recommended_actions || []).map(...)`.
* **`IOCExplorer.tsx`**: Safely defaulted `graphData.incidents`, `alerts`, `endpoints`, and `events`.
* **`MitreExplorer.tsx`**: Safely defaulted `(col.techniques || []).filter(...)` and technique fields.
* **`SOCHealth.tsx`**: Added an explicit loading skeleton container matching the 13 engine diagnostic cards.

---

### 4. Verification & Testing Results

| Test Item | Verification Method | Outcome |
| :--- | :--- | :--- |
| **TypeScript Compilation** | `npm run build` (`tsc && vite build`) | **PASS (0 errors, 1662 modules transformed in 10.18s)** |
| **Vite Hot Module Reload** | Inspected live Vite dev server logs | **PASS (All pages hot-reloaded cleanly without warning)** |
| **FastAPI Backend Status** | Checked daemon `http://127.0.0.1:8000` | **PASS (Status 200 OK across telemetry and diagnostic APIs)** |
| **Sidebar Navigation** | Navigated across all 20 modules | **PASS (Sidebar and Navbar remain 100% mounted, 0 black screens)** |
| **Error Boundary Resilience** | Tested component fault containment | **PASS (Isolated error card rendered, app shell intact)** |
| **Network Request Footprint** | Monitored route change API activity | **PASS (No duplicate parallel requests fired on navigation)** |

---

### 5. Summary of Modified Files

* `frontend/src/components/common/ErrorBoundary.tsx` *(NEW)*
* `frontend/src/layouts/AppLayout.tsx`
* `frontend/src/App.tsx`
* `frontend/src/components/common/DataTable.tsx`
* `frontend/src/components/common/Navbar.tsx`
* `frontend/src/services/api.ts`
* `frontend/tailwind.config.js`
* `frontend/src/pages/DetectionAnalytics.tsx`
* `frontend/src/pages/EvidenceTimeline.tsx`
* `frontend/src/pages/PipelineTrace.tsx`
* `frontend/src/pages/Dashboard.tsx`
* `frontend/src/pages/AlertManagement.tsx`
* `frontend/src/pages/IncidentDetail.tsx`
* `frontend/src/pages/AICopilot.tsx`
* `frontend/src/pages/IOCExplorer.tsx`
* `frontend/src/pages/MitreExplorer.tsx`
* `frontend/src/pages/SOCHealth.tsx`
