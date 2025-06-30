import React from 'react';
import { X, BarChart3, LineChart, PieChart, Table, Upload, TrendingUp, Settings } from 'lucide-react';

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

const navigation = [
  { name: 'Dashboard', href: '#', icon: BarChart3, current: true },
  { name: 'Data Import', href: '#', icon: Upload, current: false },
  { name: 'Line Charts', href: '#', icon: LineChart, current: false },
  { name: 'Bar Charts', href: '#', icon: BarChart3, current: false },
  { name: 'Pie Charts', href: '#', icon: PieChart, current: false },
  { name: 'Data Table', href: '#', icon: Table, current: false },
  { name: 'Analytics', href: '#', icon: TrendingUp, current: false },
  { name: 'Settings', href: '#', icon: Settings, current: false },
];

export function Sidebar({ open, onClose }: SidebarProps) {
  return (
    <>
      <div className={`fixed inset-0 z-50 lg:hidden ${open ? '' : 'hidden'}`}>
        <div className="fixed inset-0 bg-gray-900/80" onClick={onClose} />
        <div className="fixed inset-y-0 left-0 z-50 w-72 bg-white px-6 pb-4">
          <div className="flex h-16 shrink-0 items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Navigation</h2>
            <button
              type="button"
              className="-m-2.5 p-2.5 text-gray-700"
              onClick={onClose}
            >
              <span className="sr-only">Close sidebar</span>
              <X className="h-6 w-6" aria-hidden="true" />
            </button>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul role="list" className="flex flex-1 flex-col gap-y-7">
              <li>
                <ul role="list" className="-mx-2 space-y-1">
                  {navigation.map((item) => (
                    <li key={item.name}>
                      <a
                        href={item.href}
                        className={`group flex gap-x-3 rounded-md p-2 text-sm leading-6 font-semibold transition-colors ${
                          item.current
                            ? 'bg-blue-50 text-blue-600'
                            : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                        }`}
                      >
                        <item.icon
                          className={`h-6 w-6 shrink-0 ${
                            item.current ? 'text-blue-600' : 'text-gray-400 group-hover:text-blue-600'
                          }`}
                          aria-hidden="true"
                        />
                        {item.name}
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            </ul>
          </nav>
        </div>
      </div>

      <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-72 lg:flex-col">
        <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-white px-6 pb-4 border-r border-gray-200">
          <div className="flex h-16 shrink-0 items-center">
            <BarChart3 className="h-8 w-8 text-blue-600" />
            <span className="ml-2 text-lg font-semibold text-gray-900">Mauritania Eye</span>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul role="list" className="flex flex-1 flex-col gap-y-7">
              <li>
                <ul role="list" className="-mx-2 space-y-1">
                  {navigation.map((item) => (
                    <li key={item.name}>
                      <a
                        href={item.href}
                        className={`group flex gap-x-3 rounded-md p-2 text-sm leading-6 font-semibold transition-colors ${
                          item.current
                            ? 'bg-blue-50 text-blue-600'
                            : 'text-gray-700 hover:text-blue-600 hover:bg-gray-50'
                        }`}
                      >
                        <item.icon
                          className={`h-6 w-6 shrink-0 ${
                            item.current ? 'text-blue-600' : 'text-gray-400 group-hover:text-blue-600'
                          }`}
                          aria-hidden="true"
                        />
                        {item.name}
                      </a>
                    </li>
                  ))}
                </ul>
              </li>
            </ul>
          </nav>
        </div>
      </div>
    </>
  );
}