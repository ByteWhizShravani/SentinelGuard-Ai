'use client'

import { Users } from 'lucide-react'

export function TeamSection() {
  const teamMembers = [
    {
      name: 'Nitesh Vasave',
      role: 'AI Developer',
      description: 'Architecting the neural network engine',
    },
    {
      name: 'Varun Patil',
      role: 'ML Engineer',
      description: 'Training models for detection accuracy',
    },
    {
      name: 'Shravani Bhosekar',
      role: 'UI Designer',
      description: 'Designing the intuitive user interface',
    },
  ]

  return (
    <section id="team" className="max-w-7xl mx-auto px-6 py-16 md:py-24">
      <div className="text-center mb-12">
        <h2 className="text-4xl font-bold mb-4">Designed by Team-CodeX</h2>
        <p className="text-foreground/60 text-lg max-w-2xl mx-auto">
          A specialized unit dedicated to pioneering AI-driven cybersecurity solutions at the intersection of machine learning and human creativity
        </p>
      </div>

      <div className="grid md:grid-cols-3 gap-8">
        {teamMembers.map((member, index) => (
          <div
            key={index}
            className="glass-panel rounded-xl p-8 text-center transition hover:border-primary/45"
          >
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full border border-black/10 bg-white/82">
              <Users size={32} className="text-primary" />
            </div>
            <h3 className="font-semibold text-foreground text-lg mb-1">{member.name}</h3>
            <p className="text-primary text-sm font-semibold mb-3">{member.role}</p>
            <p className="text-foreground/60 text-sm">{member.description}</p>
          </div>
        ))}
      </div>
    </section>
  )
}
