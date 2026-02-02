import { DEFAULT_LAYOUT } from '../base';
import { AppRouteRecordRaw } from '../types';

const LOG: AppRouteRecordRaw = {
  path: '/log',
  name: 'log',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.log',
    requiresAuth: true,
    icon: 'icon-file',
    order: 2, // 放在玩家管理下方 (假设玩家管理 order 为 1)
  },
  children: [
    {
      path: 'dashboard',
      name: 'LogDashboard',
      component: () => import('@/views/log/dashboard/index.vue'),
      meta: {
        locale: 'menu.log.dashboard',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'query',
      name: 'LogQuery',
      component: () => import('@/views/log/query/index.vue'),
      meta: {
        locale: 'menu.log.query',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'config',
      name: 'LogConfig',
      component: () => import('@/views/log/config/index.vue'),
      meta: {
        locale: 'menu.log.config',
        requiresAuth: true,
        roles: ['*'],
      },
    },
  ],
};

export default LOG;
