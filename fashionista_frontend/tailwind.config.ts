import type { Config } from "tailwindcss";
import plugin from "tailwindcss/plugin";
import { PluginAPI } from "tailwindcss/types/config";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic":
          "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
      },
      boxShadow: {
        card_shadow: "0px 0px 12px 0px #D9D9D930",
      },
      fontFamily: {
        satoshi: ["var(--font-satoshi)"],
        bon_foyage: ["var(--font-bon_foyage)"],
        raleway: ["var(--font-raleway)"],
      },
      gridTemplateColumns: {
        fluid: "repeat(auto-fit, minmax(339px, 1fr))",
        card_fluid: "repeat(auto-fit, minmax(170px, 1fr))",
      },
    },
  },
  plugins: [
    plugin(function ({ addUtilities }: PluginAPI) {
      const newUtilities = {
        ".hide_scrollbar": {
          "scrollbar-width": "none",
          "-ms-overflow-style": "none",
        },
        ".hide_scrollbar::-webkit-scrollbar": {
          display: "none",
        },
      };
      addUtilities(newUtilities);
    }),
  ],
};
export default config;
