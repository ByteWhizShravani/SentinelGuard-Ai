# Design System Specification: SentinelGuard AI

## 1. Overview & Creative North Star
**Creative North Star: "The Translucent Guardian"**

This design system moves away from the aggressive, high-contrast "warning" aesthetics typical of cybersecurity. Instead, it adopts a high-end editorial approach that treats security as a seamless, invisible layer of protection. We reject the "dashboard-in-a-box" look in favor of an **Ethereal Glass** aesthetic.

The interface is defined by **intentional asymmetry** and **tonal depth**. By utilizing overlapping glass surfaces and high-end typography scales (Manrope for authority, Inter for utility), we create an environment that feels both technologically advanced and calm. This system doesn't just show data; it curates an atmosphere of premium safety.

---

## 2. Colors & Surface Philosophy

The palette is a sophisticated blend of technical blues, royal purples, and organic teals, rooted in a light, airy foundation.

### The "No-Line" Rule
Traditional 1px solid borders are strictly prohibited for sectioning. Structural boundaries must be defined through:
1.  **Background Shifts:** Transitioning from `surface` to `surface-container-low`.
2.  **Tonal Transitions:** Using soft gradients to guide the eye.
3.  **Refractive Edges:** Using the glassmorphism technique (blur + highlight) to imply a boundary.

### Surface Hierarchy & Nesting
Treat the UI as a physical stack of frosted glass sheets.
*   **Base Layer:** `surface` (#f5f7f9) – The canvas.
*   **Section Layer:** `surface-container-low` (#eef1f3) – Large content groupings.
*   **Component Layer:** `surface-container-lowest` (#ffffff) – The primary interaction cards.
*   **Active Layer:** `primary-container` (#68abff) – High-emphasis focus areas.

### The Glass & Gradient Rule
Floating elements (Modals, Hover states, Popovers) must use **Glassmorphism**:
*   **Fill:** `surface-container-lowest` at 60-80% opacity.
*   **Backdrop Blur:** 12px to 20px.
*   **Highlight:** A 1.5px inner-stroke using `outline-variant` at 20% opacity to mimic light hitting the edge of the glass.

---

## 3. Typography: Editorial Authority

We use a dual-typeface system to balance "Human" and "Machine."

*   **Display & Headlines (Manrope):** Chosen for its geometric precision and modern "tech-premium" feel. Use `display-lg` and `headline-md` with tightened letter-spacing (-0.02em) to create an authoritative, editorial header style.
*   **Body & Labels (Inter):** The workhorse. Inter provides maximum legibility for complex phishing data. 
*   **Hierarchy Note:** Use `title-lg` (Inter) for card headers but pair it with a `label-sm` (Inter, All-Caps, 0.05em tracking) for category tags to create a high-end information architecture.

---

## 4. Elevation & Depth: Tonal Layering

We convey hierarchy through "Ambient Lift" rather than structural shadows.

*   **The Layering Principle:** Place a `surface-container-lowest` card atop a `surface-container-low` background. This creates a natural 1% contrast shift that is felt rather than seen.
*   **Ambient Shadows:** For floating glass cards, use an extra-diffused shadow:
    *   `X: 0, Y: 12, Blur: 40, Spread: 0`
    *   **Color:** `on-surface` (#2c2f31) at **4% opacity**. This prevents the "muddy" look of standard shadows.
*   **Ghost Border Fallback:** If accessibility requires a stroke, use `outline-variant` (#abadaf) at **15% opacity**. Never use a 100% opaque border.

---

## 5. Components

### Buttons
*   **Primary:** A gradient fill from `primary` (#005da7) to `primary-dim` (#005192). Roundedness: `full`. No shadow, just a subtle inner-glow.
*   **Secondary (Glass):** `surface-container-lowest` at 50% opacity with a `12px` backdrop blur.
*   **Tertiary:** Transparent background, `primary` text, `title-sm` weight.

### Input Fields
*   **Style:** Background `surface-container-low`, no border.
*   **Focus State:** Background shifts to `surface-container-lowest`, with a 2px "Glass Glow" using `primary-fixed-dim` at 30% opacity.
*   **Rounding:** `md` (0.75rem).

### Cards (The Core Pattern)
*   **Standard:** `xl` (1.5rem) corner radius. Background `surface-container-lowest`. 
*   **Glass Variant:** For "Security Alerts," use a background of `secondary-container` (#d9caff) at 20% opacity with a heavy `24px` blur. This creates a soft purple "aura" that signals importance without using aggressive reds.

### Phishing Risk Indicators (Chips)
*   **Safe:** `tertiary-container` (#5bfedd) background, `on-tertiary-container` text.
*   **Suspicious:** `secondary-container` (#d9caff) background, `on-secondary-container` text.
*   **Malicious:** `error-container` (#fb5151) background, `on-error-container` text.

### Layout Elements
*   **The "Invisible" List:** Forbid divider lines. Use `0.75rem` of vertical whitespace between list items, or alternating `surface` and `surface-container-low` backgrounds for every other row.

---

## 6. Do’s and Don'ts

### Do
*   **DO** use whitespace as a functional tool. If a section feels crowded, increase the gap before adding a line.
*   **DO** overlap elements. A glass card should slightly "peek" over a background gradient to emphasize the transparency.
*   **DO** use `secondary` (Purple) and `tertiary` (Mint) for status colors to maintain the "pastel" aesthetic while keeping `error` (Red) strictly for critical blocks.

### Don't
*   **DON'T** use pure black (#000000) for anything. Use `on-surface` (#2c2f31) to maintain the soft, premium feel.
*   **DON'T** use 90-degree corners. Everything must adhere to the `Roundedness Scale` to ensure the "Lightweight" personality.
*   **DON'T** use heavy drop shadows on small elements like buttons or chips; let the color contrast do the work.
