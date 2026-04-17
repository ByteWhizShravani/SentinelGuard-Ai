'use client'

export function HeroSection() {
  return (
    <section id="home" className="max-w-7xl mx-auto px-6 py-16 md:py-24">
      <div className="grid md:grid-cols-2 gap-12 items-center">
        {/* Left Side */}
        <div className="space-y-6">
          <div className="inline-block rounded-full border border-black/10 bg-white/68 px-4 py-2 backdrop-blur-sm backdrop-saturate-150">
            <span className="text-sm font-semibold text-primary">Next-Gen Security</span>
          </div>

          <h1 className="text-5xl md:text-6xl font-bold leading-tight">
            AI-Based <br />
            <span className="gradient-text">Phishing Detection</span> <br />
            System
          </h1>

          <p className="text-lg text-foreground/70 leading-relaxed">
            Detect phishing emails & malicious URLs in real-time with our advanced neural network architecture. Secure your digital assets before threats emerge.
          </p>

          <div className="flex gap-4">
            <button className="rounded-xl bg-primary px-8 py-3 font-semibold text-white transition hover:bg-secondary">
              Check Now
            </button>
            <button className="rounded-xl border border-black/15 px-8 py-3 font-semibold text-foreground transition hover:bg-white/70">
              How it Works
            </button>
          </div>
        </div>

        {/* Right Side */}
        <div className="flex justify-center">
          <div className="glass-panel w-full max-w-xl rounded-2xl p-3">
            <video
              autoPlay
              loop
              muted
              playsInline
              preload="auto"
              src="/assets/cyber-phishing.mp4"
              className="aspect-video w-full rounded-xl bg-slate-950 object-cover [transform:translateZ(0)]"
            />
          </div>
        </div>
      </div>
    </section>
  )
}
