<template>
  <Layout>
    <template #doc-after>
      <div class="custom-footer">
        <div class="footer-content">
          <p class="footer-message">Released under the MIT License<br />Envoy Proxy is a project of the Cloud Native Computing Foundation (CNCF)</p>
          <p class="footer-copyright">Copyright © 2025 Giacomo Triggiano</p>
        </div>
      </div>
    </template>
  </Layout>
</template>

<script setup lang="ts">
import { useData } from 'vitepress'
import DefaultTheme from 'vitepress/theme'

const { Layout } = DefaultTheme
</script>

<style scoped>
.custom-footer {
  margin-top: 64px;
  padding: 32px 24px;
  border-top: 1px solid var(--vp-c-divider);
}

.footer-content {
  max-width: var(--vp-layout-max-width);
  margin: 0 auto;
  text-align: center;
}

.footer-message {
  font-size: 14px;
  color: var(--vp-c-text-2);
  margin-bottom: 8px;
}

.footer-copyright {
  font-size: 14px;
  color: var(--vp-c-text-3);
}
</style>
