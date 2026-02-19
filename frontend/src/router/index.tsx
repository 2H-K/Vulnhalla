import { createBrowserRouter, Navigate } from 'react-router-dom';
import MainLayout from '../layouts/MainLayout';
import Dashboard from '../pages/Dashboard';
import Projects from '../pages/Projects';
import ProjectNew from '../pages/ProjectNew';
import ProjectDetail from '../pages/ProjectDetail';
import Results from '../pages/Results';
import Vulnerabilities from '../pages/Vulnerabilities';
import CodeqlPackages from '../pages/CodeqlPackages';
import CodeqlGenerator from '../pages/CodeqlGenerator';
import Settings from '../pages/Settings';

const router = createBrowserRouter([
  {
    path: '/',
    element: <MainLayout />,
    children: [
      {
        index: true,
        element: <Dashboard />,
      },
      {
        path: 'projects',
        children: [
          {
            index: true,
            element: <Projects />,
          },
          {
            path: 'new',
            element: <ProjectNew />,
          },
          {
            path: ':id',
            element: <ProjectDetail />,
          },
        ],
      },
      {
        path: 'results',
        element: <Results />,
      },
      {
        path: 'vulnerabilities',
        element: <Vulnerabilities />,
      },
      {
        path: 'codeql',
        children: [
          {
            path: 'packages',
            element: <CodeqlPackages />,
          },
          {
            path: 'generator',
            element: <CodeqlGenerator />,
          },
        ],
      },
      {
        path: 'settings',
        element: <Settings />,
      },
    ],
  },
  // 捕获所有未匹配路由，重定向到首页
  {
    path: '*',
    element: <Navigate to="/" replace />,
  },
]);

export default router;
