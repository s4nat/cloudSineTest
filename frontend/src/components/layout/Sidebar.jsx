import React from 'react';
import { NavLink } from 'react-router-dom';
import { Upload, FileText } from 'lucide-react';

const Sidebar = () => {
  return (
    <aside className="w-64 bg-gray-800 text-white">
      <div className="p-4">
        <h2 className="text-xl font-semibold mb-6">File Scanner</h2>
        <nav className="space-y-2">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `flex items-center gap-2 p-2 rounded ${
                isActive ? 'bg-gray-700' : 'hover:bg-gray-700'
              }`
            }
          >
            <Upload size={20} />
            <span>Upload</span>
          </NavLink>
          <NavLink
            to="/files"
            className={({ isActive }) =>
              `flex items-center gap-2 p-2 rounded ${
                isActive ? 'bg-gray-700' : 'hover:bg-gray-700'
              }`
            }
          >
            <FileText size={20} />
            <span>Files</span>
          </NavLink>
        </nav>
      </div>
    </aside>
  );
};

export default Sidebar;