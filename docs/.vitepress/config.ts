import { defineConfig } from 'vitepress'
import { withMermaid } from "vitepress-plugin-mermaid"
import { version } from './version'

const defaultConfiguration = defineConfig({
  title: "Envoy Authorization Service",
  description:
    "A flexible, policy-driven authorization framework for Envoy Proxy with observability built-in",
  base: "/envoy-authorization-service/",

  head: [
    ["link", { rel: "icon", href: "/envoy-authorization-service/favicon.ico" }],
  ],

  themeConfig: {
    logo: "/logo.drawio.svg",

    nav: [
      { text: "Get Started", link: "/get-started" },
      {
        text: "Guides",
        items: [
          { text: "Docker Deployment", link: "/guides/docker" },
          { text: "Kubernetes Deployment", link: "/guides/kubernetes" },
          { text: "Observability", link: "/guides/observability" },
        ],
      },
      { text: "Use Cases", link: "/examples/" },
      {
        text: "Controllers",
        items: [
          { text: "Analysis Controllers", link: "/analysis-controllers/" },
          { text: "Match Controllers", link: "/match-controllers/" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "CLI", link: "/reference/cli" },
          { text: "Headers", link: "/reference/headers" },
          { text: "Metrics", link: "/reference/metrics" },
        ],
      },
      {
        text: `v${version}`,
        items: [
          {
            text: "Changelog",
            link: "https://github.com/gtriggiano/envoy-authorization-service/blob/main/CHANGELOG.md",
          },
          {
            text: "Releases",
            link: "https://github.com/gtriggiano/envoy-authorization-service/releases",
          },
        ],
      },
    ],

    sidebar: {
      "/": [
        {
          text: "Introduction",
          items: [
            { text: "What is it?", link: "/index" },
            { text: "Get Started", link: "/get-started" },
            { text: "Configuration", link: "/configuration" },
            {
              text: "Authorization Policy DSL",
              link: "/policy-dsl",
            },
            { text: "Architecture", link: "/architecture" },
          ],
        },
        {
          text: "Guides",
          items: [
            { text: "Docker Deployment", link: "/guides/docker" },
            { text: "Kubernetes Deployment", link: "/guides/kubernetes" },
            { text: "Observability", link: "/guides/observability" },
          ],
        },
        {
          text: "Use Cases",
          link: "/examples/",
          items: [
            {
              text: "Zero-Trust Partner Webhooks",
              link: "/examples/partner-webhooks-zero-trust",
            },
            {
              text: "Regional Compliance with Geofences and ISP Guardrails",
              link: "/examples/regional-compliance-geofence-asn",
            },
            {
              text: "SaaS Admin Console with Live IP Allowlists",
              link: "/examples/saas-admin-live-ip-allowlist",
            },
            {
              text: "Bot-Resistant Signup & Trial Forms",
              link: "/examples/signup-bot-shield",
            },
            {
              text: "Geofenced Store Tablets & Kiosks",
              link: "/examples/store-tablet-geo-ua",
            },
          ],
        },
        {
          text: "Analysis Controllers",
          items: [
            { text: "Overview", link: "/analysis-controllers/" },
            { text: "MaxMind ASN", link: "/analysis-controllers/maxmind-asn" },
            {
              text: "MaxMind GeoIP",
              link: "/analysis-controllers/maxmind-geoip",
            },
            {
              text: "User-Agent Detect",
              link: "/analysis-controllers/ua-detect",
            },
          ],
        },
        {
          text: "Match Controllers",
          items: [
            { text: "Overview", link: "/match-controllers/" },
            { text: "ASN Match", link: "/match-controllers/asn-match" },
            {
              text: "ASN Match Database",
              link: "/match-controllers/asn-match-database",
            },
            {
              text: "Geofence Match",
              link: "/match-controllers/geofence-match",
            },
            { text: "IP Match", link: "/match-controllers/ip-match" },
            {
              text: "IP Match Database",
              link: "/match-controllers/ip-match-database",
            },
          ],
        },
        {
          text: "Reference",
          items: [
            { text: "CLI", link: "/reference/cli" },
            { text: "Headers", link: "/reference/headers" },
            { text: "Metrics", link: "/reference/metrics" },
          ],
        },
      ],
    },

    socialLinks: [
      {
        icon: "github",
        link: "https://github.com/gtriggiano/envoy-authorization-service",
      },
    ],

    search: {
      provider: "local",
    },

    editLink: {
      pattern:
        "https://github.com/gtriggiano/envoy-authorization-service/edit/main/docs/:path",
      text: "Edit this page on GitHub",
    },

    footer: {
      message:
        "Released under the MIT License<br />Envoy Proxy is a project of the Cloud Native Computing Foundation (CNCF)",
      copyright: "Copyright © 2025 Giacomo Triggiano",
    },

    lastUpdated: {
      text: "Updated at",
      formatOptions: {
        dateStyle: "short",
        timeStyle: "short",
      },
    },
  },

  markdown: {
    theme: {
      light: "github-light",
      dark: "github-dark",
    },
    lineNumbers: true,
    config: (md) => {
      // Replace {{VERSION}} with actual version in all markdown content
      md.core.ruler.before("normalize", "replace-version", (state) => {
        state.src = state.src.replace(/\{\{VERSION\}\}/g, version);
      });
    },
  },
});

export default withMermaid({
  ...defaultConfiguration,
  mermaid: {}
})
