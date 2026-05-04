import type { AppRouteRecordRaw } from '../types';
import { DEFAULT_LAYOUT } from '../base';

const TRACEABILITY: AppRouteRecordRaw = {
  path: '/traceability',
  name: 'traceability',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.traceability',
    requiresAuth: true,
    icon: 'icon-unordered-list',
    order: 5,
  },
  children: [
    {
      path: 'dashboard',
      name: 'TraceabilityDashboard',
      component: () => import('@/views/traceability/dashboard/index.vue'),
      meta: {
        locale: 'menu.traceability.dashboard',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'config',
      name: 'TraceabilityConfig',
      component: () => import('@/views/traceability/config/index.vue'),
      meta: {
        locale: 'menu.traceability.config',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'query',
      name: 'TraceabilityQuery',
      component: () => import('@/views/traceability/query/index.vue'),
      meta: {
        locale: 'menu.traceability.query',
        requiresAuth: true,
        roles: ['*'],
      },
    },
  ],
};

export default TRACEABILITY;
