import { getAdvisories } from "@/actions/advisories";
import Link from "next/link";

export default async function AdvisoriesPage(props: {
  searchParams: Promise<{ page?: string; search?: string; ransomware?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const { advisories, total, pages } = await getAdvisories({
    page,
    search: searchParams.search,
    ransomware: searchParams.ransomware === "true",
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Advisories (CISA KEV)</h1>
        <p className="text-sm text-[var(--text-secondary)]">{total.toLocaleString()} known exploited vulnerabilities</p>
      </div>

      <form className="flex gap-3" action="/advisories">
        <input type="search" name="search" placeholder="Search CVE, vendor, product..." defaultValue={searchParams.search ?? ""} className="flex-1" />
        <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
          <input type="checkbox" name="ransomware" value="true" defaultChecked={searchParams.ransomware === "true"} />
          Ransomware only
        </label>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[var(--text-secondary)] text-xs">
              <th className="pb-2">CVE</th>
              <th className="pb-2">Vulnerability</th>
              <th className="pb-2">Vendor / Product</th>
              <th className="pb-2">Added</th>
              <th className="pb-2">Due</th>
              <th className="pb-2">Ransomware</th>
            </tr>
          </thead>
          <tbody>
            {advisories.map((a) => (
              <tr key={a.id} className="table-row">
                <td className="py-2">
                  <Link href={`/advisories/${a.id}`} className="font-mono text-[var(--accent)] hover:underline">
                    {a.cveId ?? a.advisoryId}
                  </Link>
                </td>
                <td className="py-2 max-w-sm truncate">{a.title}</td>
                <td className="py-2 text-[var(--text-secondary)]">{a.vendorProject} — {a.product}</td>
                <td className="py-2 text-[var(--text-secondary)]">
                  {a.dateAdded && new Date(a.dateAdded).toLocaleDateString()}
                </td>
                <td className="py-2 text-[var(--text-secondary)]">
                  {a.dueDate && new Date(a.dueDate).toLocaleDateString()}
                </td>
                <td className="py-2">
                  {a.knownRansomware && <span className="badge bg-red-900/50 text-red-400">Yes</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={`/advisories?page=${page - 1}&search=${searchParams.search ?? ""}&ransomware=${searchParams.ransomware ?? ""}`} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Prev</Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">Page {page} of {pages}</span>
          {page < pages && (
            <Link href={`/advisories?page=${page + 1}&search=${searchParams.search ?? ""}&ransomware=${searchParams.ransomware ?? ""}`} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Next</Link>
          )}
        </div>
      )}
    </div>
  );
}
