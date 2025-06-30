import React from 'react';
import { Menu, Download, Settings, User } from 'lucide-react';

interface HeaderProps {
  onMenuClick: () => void;
}

export function Header({ onMenuClick }: HeaderProps) {
  return (
    <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-gray-200 bg-white px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
      <button
        type="button"
        className="-m-2.5 p-2.5 text-gray-700 lg:hidden"
        onClick={onMenuClick}
      >
        <span className="sr-only">Open sidebar</span>
        <Menu className="h-6 w-6" aria-hidden="true" />
      </button>

      <div className="h-6 w-px bg-gray-200 lg:hidden" aria-hidden="true" />

      <div className="flex flex-1 justify-between">
        <div className="flex items-center">
          <h1 className="text-xl font-semibold text-gray-900">
            Mauritania Eye Tool
          </h1>
        </div>

        <div className="flex items-center gap-x-4 lg:gap-x-6">
          <button
            type="button"
            className="flex items-center gap-2 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export Data
          </button>

          <button
            type="button"
            className="-m-1.5 flex items-center p-1.5 text-gray-400 hover:text-gray-500 transition-colors"
          >
            <Settings className="h-6 w-6" />
            <span className="sr-only">Settings</span>
          </button>

          <button
            type="button"
            className="-m-1.5 flex items-center p-1.5 text-gray-400 hover:text-gray-500 transition-colors"
          >
            <User className="h-6 w-6" />
            <span className="sr-only">User menu</span>
          </button>
        </div>
      </div>
    </div>
  );
}