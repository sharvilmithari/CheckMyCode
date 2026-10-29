"use client";

import Link from "next/link";
import Image from "next/image";
import { Terminal, Menu, X } from "lucide-react";
import { useState } from "react";
import ThemeToggle from "@/components/ui/ThemeToggle";

export default function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <header className="w-full border-b border-border bg-background/80 backdrop-blur-md sticky top-0 z-50 transition-colors">
      <div className="max-w-[1240px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative h-8 flex items-center">
            <Image
              src="/logo.png"
              alt="CheckMyCode"
              width={132}
              height={32}
              className="logo-dark h-8 w-auto object-contain"
              priority
            />
            <Image
              src="/logo-light.png"
              alt="CheckMyCode"
              width={132}
              height={32}
              className="logo-light h-8 w-auto object-contain"
              priority
            />
          </div>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-5 text-sm font-medium text-text-secondary">
          <Link
            href="/#how-it-works"
            className="hover:text-text-primary transition-colors flex items-center gap-1.5"
          >
            <Terminal className="w-4 h-4 text-accent" />
            How It Works
          </Link>
          <Link
            href="/terms"
            className="hover:text-text-primary transition-colors"
          >
            Terms
          </Link>
          <Link
            href="/privacy"
            className="hover:text-text-primary transition-colors"
          >
            Privacy
          </Link>
          <ThemeToggle />
          <Link
            href="/scan"
            className="ml-1 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-sm font-semibold transition-all shadow-md shadow-primary/20 flex items-center gap-2"
          >
            Scan My Project
          </Link>
        </nav>

        {/* Mobile menu and theme toggle */}
        <div className="flex md:hidden items-center gap-2">
          <ThemeToggle />
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 text-text-secondary hover:text-text-primary focus:outline-none"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-border bg-surface px-4 py-4 space-y-3">
          <Link
            href="/#how-it-works"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-text-secondary hover:text-text-primary flex items-center gap-2"
          >
            <Terminal className="w-4 h-4 text-accent" />
            How It Works
          </Link>
          <Link
            href="/terms"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-text-secondary hover:text-text-primary"
          >
            Terms & Conditions
          </Link>
          <Link
            href="/privacy"
            onClick={() => setMobileMenuOpen(false)}
            className="block py-2 text-text-secondary hover:text-text-primary"
          >
            Privacy Policy
          </Link>
          <Link
            href="/scan"
            onClick={() => setMobileMenuOpen(false)}
            className="block w-full text-center py-2.5 px-4 rounded-lg bg-primary text-white font-semibold shadow-md shadow-primary/20"
          >
            Scan My Project
          </Link>
        </div>
      )}
    </header>
  );
}
