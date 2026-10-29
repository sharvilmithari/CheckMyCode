import Link from "next/link";
import Image from "next/image";
import { Lock, Cpu, ArrowUpRight } from "lucide-react";

export default function Footer() {
  return (
    <footer className="w-full border-t border-border bg-background-secondary/50 pt-12 pb-8 mt-16 text-sm text-text-muted transition-colors">
      <div className="max-w-[1240px] mx-auto px-4 sm:px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          {/* Brand Column */}
          <div className="md:col-span-2 space-y-3">
            <div className="relative h-7 flex items-center">
              <Image
                src="/logo.png"
                alt="CheckMyCode"
                width={124}
                height={28}
                className="logo-dark h-7 w-auto object-contain"
              />
              <Image
                src="/logo-light.png"
                alt="CheckMyCode"
                width={124}
                height={28}
                className="logo-light h-7 w-auto object-contain"
              />
            </div>
            <p className="text-text-secondary text-sm max-w-sm leading-relaxed">
              Find security vulnerabilities, exposed secrets, and risky configurations before they become deployment problems.
            </p>
            <div className="flex items-center gap-4 pt-2 text-xs text-text-muted">
              <span className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-accent" />
                Zero code execution
              </span>
              <span className="flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-primary" />
                Offline rule checks
              </span>
            </div>
          </div>

          {/* Platform Links */}
          <div className="space-y-3">
            <h4 className="text-xs uppercase font-bold tracking-wider text-text-primary">
              Platform
            </h4>
            <ul className="space-y-2 text-text-secondary">
              <li>
                <Link href="/scan" className="hover:text-text-primary transition-colors flex items-center gap-1">
                  Security Scanner <ArrowUpRight className="w-3 h-3 opacity-60" />
                </Link>
              </li>
              <li>
                <Link href="/#how-it-works" className="hover:text-text-primary transition-colors">
                  How It Works
                </Link>
              </li>
              <li>
                <Link href="/#capabilities" className="hover:text-text-primary transition-colors">
                  Detection Capabilities
                </Link>
              </li>
            </ul>
          </div>

          {/* Legal & Trust */}
          <div className="space-y-3">
            <h4 className="text-xs uppercase font-bold tracking-wider text-text-primary">
              Legal & Trust
            </h4>
            <ul className="space-y-2 text-text-secondary">
              <li>
                <Link href="/terms" className="hover:text-text-primary transition-colors">
                  Terms & Conditions
                </Link>
              </li>
              <li>
                <Link href="/privacy" className="hover:text-text-primary transition-colors">
                  Privacy Policy
                </Link>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom copyright line */}
        <div className="pt-8 border-t border-border/60 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs">
          <p>
            &copy; {new Date().getFullYear()} CheckMyCode. Powered by OpenGuard security engine.
          </p>
          <p className="text-text-muted text-center sm:text-right">
            Rule-based static analysis &middot; Not a substitute for formal manual penetration testing.
          </p>
        </div>
      </div>
    </footer>
  );
}
