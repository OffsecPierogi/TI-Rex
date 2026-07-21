"use client";

import { useState } from "react";
import { updateUserRole, deleteUser } from "@/actions/auth";

interface UserRow {
  id: string;
  email: string;
  name: string | null;
  role: string;
  createdAt: string;
}

const ROLE_COLORS: Record<string, string> = {
  ADMIN: "bg-red-900/30 text-red-400",
  EDITOR: "bg-amber-900/30 text-amber-400",
  READER: "bg-emerald-900/30 text-emerald-400",
};

export function UserManagement({
  users: initialUsers,
  currentUserId,
}: {
  users: UserRow[];
  currentUserId: string;
}) {
  const [users, setUsers] = useState(initialUsers);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleRoleChange(userId: string, role: "READER" | "EDITOR" | "ADMIN") {
    setBusy(userId);
    setError(null);
    const result = await updateUserRole(userId, role);
    if (result.error) {
      setError(result.error);
    } else {
      setUsers((prev) => prev.map((u) => (u.id === userId ? { ...u, role } : u)));
    }
    setBusy(null);
  }

  async function handleDelete(userId: string, email: string) {
    if (!confirm(`Delete user ${email}? This cannot be undone.`)) return;
    setBusy(userId);
    setError(null);
    const result = await deleteUser(userId);
    if (result.error) {
      setError(result.error);
    } else {
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    }
    setBusy(null);
  }

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-4">User Management</h2>

      {error && (
        <div className="mb-4 px-3 py-2 rounded-lg bg-red-900/30 border border-red-800 text-red-400 text-sm">
          {error}
        </div>
      )}

      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-[var(--text-secondary)] text-xs">
            <th className="pb-2">User</th>
            <th className="pb-2">Email</th>
            <th className="pb-2">Role</th>
            <th className="pb-2">Joined</th>
            <th className="pb-2"></th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => {
            const isCurrentUser = user.id === currentUserId;
            return (
              <tr key={user.id} className="table-row">
                <td className="py-2">
                  {user.name || "—"}
                  {isCurrentUser && (
                    <span className="ml-1.5 text-[10px] text-[var(--text-secondary)]">(you)</span>
                  )}
                </td>
                <td className="py-2 text-[var(--text-secondary)]">{user.email}</td>
                <td className="py-2">
                  {isCurrentUser ? (
                    <span className={`badge ${ROLE_COLORS[user.role]}`}>{user.role}</span>
                  ) : (
                    <select
                      value={user.role}
                      onChange={(e) =>
                        handleRoleChange(user.id, e.target.value as "READER" | "EDITOR" | "ADMIN")
                      }
                      disabled={busy === user.id}
                      className="text-xs py-1 px-2"
                    >
                      <option value="READER">READER</option>
                      <option value="EDITOR">EDITOR</option>
                      <option value="ADMIN">ADMIN</option>
                    </select>
                  )}
                </td>
                <td className="py-2 text-[var(--text-secondary)] text-xs">
                  {new Date(user.createdAt).toLocaleDateString()}
                </td>
                <td className="py-2 text-right">
                  {!isCurrentUser && (
                    <button
                      onClick={() => handleDelete(user.id, user.email)}
                      disabled={busy === user.id}
                      className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
