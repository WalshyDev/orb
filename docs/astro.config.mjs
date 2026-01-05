import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightAutoSidebar from 'starlight-auto-sidebar';

export default defineConfig({
  site: 'https://orb.dev',
  integrations: [
    starlight({
      title: 'Orb',
      description: 'A modern HTTP client CLI tool written in Rust',
      customCss: ['./src/styles/custom.css'],
      plugins: [starlightAutoSidebar()],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/WalshyDev/orb' },
      ],
      editLink: {
        baseUrl: 'https://github.com/WalshyDev/orb/edit/main/packages/orb-docs/',
      },
      sidebar: [
        {
          label: 'Getting Started',
          autogenerate: { directory: 'getting-started' },
        },
        {
          label: 'CLI Reference',
          autogenerate: { directory: 'cli' },
        },
        {
          label: 'orb-mockhttp',
          autogenerate: { directory: 'mockhttp' },
        },
        {
          label: 'Contributing',
          autogenerate: { directory: 'contributing' },
        },
      ],
    }),
  ],
});
