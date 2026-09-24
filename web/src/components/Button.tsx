// Drishti v0.1 — reusable Flame Button component | Serenity UI / 21st.dev integration
import clsx from "clsx";
import { Loader2 } from "lucide-react";
import React, {
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";

export type ButtonVariant = "primary" | "ghost" | "danger" | "flame";
export type ButtonSize = "sm" | "md" | "lg";
export type FlameTheme = "auto" | "fire" | "cyber" | "danger" | "ghost" | "none";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  flame?: FlameTheme;
  children: ReactNode;
}

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "bg-accent-500 text-canvas font-semibold border border-accent-400 shadow-[0_0_15px_rgba(0,255,102,0.25)] hover:bg-accent-400 hover:shadow-[0_0_24px_rgba(0,255,102,0.45)] active:bg-accent-600 disabled:opacity-50",
  flame:
    "bg-gradient-to-r from-zinc-900 via-zinc-800 to-zinc-900 text-[#ffe2c2] font-bold border border-orange-500/40 hover:border-orange-400/80 shadow-[0_0_15px_rgba(255,106,45,0.25)] active:bg-zinc-950 disabled:opacity-50 uppercase tracking-wider",
  ghost:
    "bg-surface-2/80 text-ink-primary hover:bg-surface-3 hover:text-accent-400 border border-hairline shadow-md backdrop-blur-md hover:border-accent-500/40 hover:shadow-[0_0_12px_rgba(0,255,102,0.15)] disabled:opacity-50",
  danger:
    "bg-[#180a0e] text-risk-critical border border-risk-critical/40 hover:bg-risk-critical/20 hover:border-risk-critical/70 hover:shadow-[0_0_16px_rgba(239,68,68,0.3)] disabled:opacity-50",
};

const SIZES: Record<ButtonSize, string> = {
  sm: "text-[12px] px-3 py-1.5 gap-1.5 tracking-wide",
  md: "text-[14px] px-5 py-2.5 gap-2 tracking-wide",
  lg: "text-[15px] px-6 py-3 gap-2.5 tracking-wide",
};

const RADIUS_SIZES: Record<ButtonSize, string> = {
  sm: "rounded-md",
  md: "rounded-lg",
  lg: "rounded-xl",
};

interface FlameConfig {
  outerGlow: (xPercent: number) => string;
  innerBulb: string;
  innerHalo: string;
  mixBlend: React.CSSProperties["mixBlendMode"];
}

const FLAME_CONFIGS: Record<Exclude<FlameTheme, "auto" | "none">, FlameConfig> = {
  // Classic warm flame from 21st.dev / Serenity UI
  fire: {
    outerGlow: (x) => `radial-gradient(ellipse 46% 85% at ${x}% 50%,
      rgba(255, 214, 130, 1) 0%,
      rgba(255, 106, 45, 0.95) 28%,
      rgba(255, 45, 85, 0.5) 50%,
      rgba(255, 45, 85, 0.12) 68%,
      transparent 80%)`,
    innerBulb:
      "radial-gradient(50% 50% at 50% 50%, #FFFFF5 3.5%, rgba(255, 106, 45, 1) 26.5%, #FFDA9F 37.5%, rgba(255, 106, 45, 0.5) 49%, rgba(255, 45, 85, 0) 92.5%)",
    innerHalo:
      "radial-gradient(43.3% 44.23% at 50% 49.51%, #FFFFF7 29%, #FFFACD 48.5%, #F4D2BF 60.71%, rgba(214, 211, 210, 0) 100%)",
    mixBlend: "screen",
  },
  // Drishti Cyber Matrix plasma flame
  cyber: {
    outerGlow: (x) => `radial-gradient(ellipse 48% 85% at ${x}% 50%,
      rgba(220, 255, 235, 1) 0%,
      rgba(0, 255, 102, 0.92) 28%,
      rgba(0, 204, 102, 0.5) 50%,
      rgba(0, 255, 102, 0.12) 68%,
      transparent 82%)`,
    innerBulb:
      "radial-gradient(50% 50% at 50% 50%, #FFFFFF 3.5%, rgba(0, 255, 102, 1) 26.5%, #A7F3D0 37.5%, rgba(0, 255, 102, 0.55) 49%, rgba(0, 204, 102, 0) 92.5%)",
    innerHalo:
      "radial-gradient(43.3% 44.23% at 50% 49.51%, #F0FDF4 29%, #BBF7D0 48.5%, rgba(0, 255, 102, 0.35) 60.71%, rgba(0, 255, 102, 0) 100%)",
    mixBlend: "screen",
  },
  // Incident critical / danger fiery glow
  danger: {
    outerGlow: (x) => `radial-gradient(ellipse 46% 85% at ${x}% 50%,
      rgba(255, 180, 140, 1) 0%,
      rgba(239, 68, 68, 0.95) 28%,
      rgba(220, 38, 38, 0.55) 50%,
      rgba(220, 38, 38, 0.14) 68%,
      transparent 80%)`,
    innerBulb:
      "radial-gradient(50% 50% at 50% 50%, #FFF5F5 3.5%, rgba(239, 68, 68, 1) 26.5%, #FCA5A5 37.5%, rgba(220, 38, 38, 0.5) 49%, rgba(185, 28, 28, 0) 92.5%)",
    innerHalo:
      "radial-gradient(43.3% 44.23% at 50% 49.51%, #FFF5F5 29%, #FED7AA 48.5%, #FCA5A5 60.71%, rgba(239, 68, 68, 0) 100%)",
    mixBlend: "screen",
  },
  // Ghost secondary technical glow
  ghost: {
    outerGlow: (x) => `radial-gradient(ellipse 46% 85% at ${x}% 50%,
      rgba(167, 243, 208, 0.7) 0%,
      rgba(0, 255, 102, 0.45) 28%,
      rgba(5, 150, 105, 0.25) 50%,
      rgba(0, 255, 102, 0.08) 68%,
      transparent 80%)`,
    innerBulb:
      "radial-gradient(50% 50% at 50% 50%, #FFFFFF 3.5%, rgba(0, 255, 102, 0.45) 26.5%, #A7F3D0 37.5%, rgba(0, 255, 102, 0.22) 49%, rgba(0, 204, 102, 0) 92.5%)",
    innerHalo:
      "radial-gradient(43.3% 44.23% at 50% 49.51%, #F0FDF4 25%, rgba(187, 247, 208, 0.35) 45%, rgba(0, 255, 102, 0.15) 60%, rgba(0, 255, 102, 0) 100%)",
    mixBlend: "screen",
  },
};

function resolveFlameTheme(variant: ButtonVariant, flame?: FlameTheme): FlameConfig | null {
  if (flame === "none") return null;
  if (flame && flame !== "auto") return FLAME_CONFIGS[flame];

  if (variant === "flame") return FLAME_CONFIGS.fire;
  if (variant === "danger") return FLAME_CONFIGS.danger;
  if (variant === "ghost") return FLAME_CONFIGS.ghost;
  return FLAME_CONFIGS.cyber;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  flame = "auto",
  disabled,
  children,
  className = "",
  type = "button",
  ...rest
}: ButtonProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const rectRef = useRef<DOMRect | null>(null);
  const [cursorX, setCursorX] = useState<number | null>(null);
  const [btnWidth, setBtnWidth] = useState<number>(0);
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const [glowOpacity, setGlowOpacity] = useState<number>(0);
  const targetOpacityRef = useRef<number>(0);

  const flameConfig = resolveFlameTheme(variant, flame);

  const handleMouseEnter = () => {
    if (disabled || loading) return;
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      rectRef.current = rect;
      setBtnWidth(rect.width);
    }
    setIsHovered(true);
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (disabled || loading) return;
    const rect = rectRef.current;
    if (rect) {
      setCursorX(e.clientX - rect.left);
    }
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
  };

  // Cursor flare calculation — smooth physics derived from 21st.dev flame algorithm
  const activeX = cursorX ?? (btnWidth ? btnWidth / 2 : 50);
  const ratio = btnWidth > 0 ? Math.max(0, Math.min(1, activeX / btnWidth)) : 0.5;
  const isRightSide = ratio >= 0.5;

  // Flare intensity flares towards the extremities
  const flareIntensity = Math.min(1, Math.abs(ratio - 0.5) * 2) ** 1.5;
  const targetOpacity =
    isHovered && !disabled && !loading && flameConfig
      ? Math.min(1, 0.7 + flareIntensity * 0.3)
      : 0;

  useEffect(() => {
    targetOpacityRef.current = targetOpacity;
  }, [targetOpacity]);

  // RequestAnimationFrame lerp loop for liquid, buttery glow transitions
  useEffect(() => {
    let animId: number | null = null;
    const updateLoop = () => {
      setGlowOpacity((prev) => {
        const target = targetOpacityRef.current;
        const diff = target - prev;
        if (Math.abs(diff) < 0.003) {
          animId = null;
          return target;
        }
        animId = requestAnimationFrame(updateLoop);
        return prev + diff * 0.18;
      });
    };

    if (Math.abs(targetOpacity - glowOpacity) > 0.003 && animId === null) {
      animId = requestAnimationFrame(updateLoop);
    }

    return () => {
      if (animId !== null) cancelAnimationFrame(animId);
    };
  }, [targetOpacity, glowOpacity]);

  // Smooth focal point of the outer flame ellipse (flares near outer edges)
  const glowX = isRightSide ? 86 : 14;

  // Distribute layout classes cleanly to container wrapper and button
  const classList = className.split(/\s+/).filter(Boolean);
  const isFullWidth = classList.includes("w-full");
  const isFlex1 = classList.includes("flex-1");
  const isPill = classList.some((c) => c.includes("rounded-full"));
  const radiusClass = isPill ? "rounded-full" : RADIUS_SIZES[size];

  // Wrapper captures positioning and margins to prevent layout breaks
  const wrapperLayoutClasses = classList
    .filter((c) =>
      /^(m[trblxy]?-\S+|mx-auto|ml-auto|mr-auto|self-\S+|justify-self-\S+|col-span-\S+|row-span-\S+)/.test(
        c,
      ),
    )
    .join(" ");

  // Button retains typography, specific paddings/heights, and visual overrides
  const buttonVisualClasses = classList
    .filter(
      (c) =>
        !/^(m[trblxy]?-\S+|mx-auto|ml-auto|mr-auto|self-\S+|justify-self-\S+|col-span-\S+|row-span-\S+)/.test(
          c,
        ),
    )
    .join(" ");

  return (
    <div
      ref={containerRef}
      onMouseEnter={handleMouseEnter}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={clsx(
        "relative inline-flex items-center justify-center isolate group/flame select-none",
        radiusClass,
        isFullWidth && "w-full",
        isFlex1 && "flex-1",
        wrapperLayoutClasses,
      )}
    >
      {/* ── Outer Flame Glow (21st.dev Flame Layer) ────────────────────────── */}
      {flameConfig && (
        <div
          className={clsx(
            "absolute pointer-events-none -z-10 transition-all duration-75",
            radiusClass,
          )}
          style={{
            inset: size === "sm" ? "-5px" : "-7px",
            background: flameConfig.outerGlow(glowX),
            filter: "blur(8px) saturate(1.4)",
            opacity: glowOpacity,
          }}
          aria-hidden="true"
        />
      )}

      {/* ── Core Button Element ───────────────────────────────────────────── */}
      <button
        type={type}
        className={clsx(
          "relative z-10 w-full inline-flex items-center justify-center font-medium overflow-hidden",
          "transition-colors duration-150",
          "motion-safe:transition-[color,background-color,border-color,transform] motion-safe:active:scale-[0.98]",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/70",
          "disabled:cursor-not-allowed",
          radiusClass,
          VARIANTS[variant],
          SIZES[size],
          buttonVisualClasses,
        )}
        disabled={disabled || loading}
        {...rest}
      >
        {/* ── Inner Cursor Flame Tracker (Core Bulb & Heat Halo) ───────────── */}
        {flameConfig && (
          <div
            className={clsx(
              "absolute inset-0 pointer-events-none -z-0 overflow-hidden",
              radiusClass,
            )}
            style={{
              opacity: isHovered && !disabled && !loading ? 1 : 0,
              transition: "opacity 160ms ease-out",
            }}
            aria-hidden="true"
          >
            {/* Core Bulb */}
            <div
              className="absolute rounded-full pointer-events-none"
              style={{
                width: 124,
                height: 124,
                left: activeX - 62,
                top: "50%",
                transform: "translateY(-50%)",
                background: flameConfig.innerBulb,
                mixBlendMode: flameConfig.mixBlend,
              }}
            />
            {/* Ambient Halo */}
            <div
              className="absolute rounded-full pointer-events-none"
              style={{
                width: 204,
                height: 104,
                left: activeX - 102,
                top: "50%",
                transform: "translateY(-50%)",
                filter: "blur(5px)",
                background: flameConfig.innerHalo,
                mixBlendMode: flameConfig.mixBlend,
              }}
            />
          </div>
        )}

        {/* ── Content & Loading Spinner ────────────────────────────────────── */}
        <span className="relative z-10 inline-flex items-center justify-center gap-2 pointer-events-none">
          {loading && <Loader2 className="h-4 w-4 animate-spin shrink-0" aria-hidden="true" />}
          {children}
        </span>
      </button>
    </div>
  );
}
