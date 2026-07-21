import { prisma } from "@/lib/db";
import Link from "next/link";

export default async function CategoriesPage() {
  const categories = await prisma.category.findMany({
    include: {
      _count: { select: { techniques: true, actors: true } },
    },
    orderBy: { name: "asc" },
  });

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Categories</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Browse techniques and actors by operational category
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {categories.map((c) => (
          <Link key={c.id} href={`/categories/${c.slug}`} className="card hover:border-[var(--accent)] transition-colors">
            <div className="flex items-center gap-3 mb-3">
              <span className="w-4 h-4 rounded-full shrink-0" style={{ background: c.color ?? "#666" }} />
              <h2 className="text-lg font-semibold">{c.name}</h2>
            </div>
            <p className="text-xs text-[var(--text-secondary)] mb-4 line-clamp-2">{c.description}</p>
            <div className="flex gap-4 text-sm">
              <span className="text-[var(--text-primary)]">{c._count.techniques} <span className="text-[var(--text-secondary)] text-xs">techniques</span></span>
              <span className="text-[var(--text-primary)]">{c._count.actors} <span className="text-[var(--text-secondary)] text-xs">actors</span></span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
