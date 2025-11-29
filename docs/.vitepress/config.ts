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
    logo: "/logo.svg",

    nav: [
      { text: "Intro", link: "/getting-started" },
      { text: "Configuration", link: "/configuration/" },
      { text: "Examples", link: "/examples/" },
      {
        text: "Reference",
        items: [
          { text: "CLI Commands", link: "/reference/cli" },
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
            { text: "Getting Started", link: "/getting-started" },
            { text: "Architecture", link: "/architecture" },
          ],
        },
        {
          text: "Configuration",
          items: [
            { text: "Overview", link: "/configuration/" },
            {
              text: "Analysis Controllers",
              link: "/configuration/analysis-controllers",
            },
            {
              text: "Authorization Controllers",
              link: "/configuration/authorization-controllers",
            },
            { text: "Policy DSL", link: "/configuration/policy-dsl" },
            { text: "Server & Metrics", link: "/configuration/server-metrics" },
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
          text: "Examples",
          items: [
            { text: "Overview", link: "/examples/" },
            { text: "IP Match", link: "/examples/ip-match" },
            {
              text: "IP Match - Redis",
              link: "/examples/ip-match-redis",
            },
            { text: "ASN Match", link: "/examples/asn-match" },
            { text: "Combined Policies", link: "/examples/combined-policy" },
          ],
        },
        {
          text: "Reference",
          items: [
            { text: "CLI Commands", link: "/reference/cli" },
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
      message: "Released under the MIT License.",
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