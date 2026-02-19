import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Menu, Typography } from 'antd';
import {
  DashboardOutlined,
  FolderOutlined,
  FileSearchOutlined,
  SettingOutlined,
  CodeOutlined,
  RobotOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import './MainLayout.css';

const { Header, Sider, Content } = Layout;
const { Title } = Typography;

const menuItems = [
  {
    key: '/',
    icon: <DashboardOutlined />,
    label: '仪表盘',
  },
  {
    key: '/projects',
    icon: <FolderOutlined />,
    label: '项目管理',
  },
  {
    key: '/vulnerabilities',
    icon: <SafetyOutlined />,
    label: '漏洞列表',
  },
  {
    key: '/results',
    icon: <FileSearchOutlined />,
    label: '分析结果',
  },
  {
    key: 'codeql',
    icon: <CodeOutlined />,
    label: 'CodeQL',
    children: [
      {
        key: '/codeql/packages',
        icon: <CodeOutlined />,
        label: '包管理',
      },
      {
        key: '/codeql/generator',
        icon: <RobotOutlined />,
        label: 'LLM生成查询',
      },
    ],
  },
  {
    key: '/settings',
    icon: <SettingOutlined />,
    label: '设置',
  },
];

const MainLayout = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key);
  };

  // 获取当前选中的菜单项
  const getSelectedKeys = () => {
    const path = location.pathname;
    if (path.startsWith('/codeql/')) {
      return [path];
    }
    return [path];
  };

  // 获取展开的菜单项
  const getOpenKeys = () => {
    const path = location.pathname;
    if (path.startsWith('/codeql/')) {
      return ['codeql'];
    }
    return [];
  };

  return (
    <Layout className="main-layout">
      <Sider
        theme="dark"
        width={220}
        className="sidebar"
        breakpoint="lg"
        collapsedWidth="0"
      >
        <div className="logo">
          <Title level={4} style={{ color: '#fff', margin: 0 }}>
            🔥 Vulnhalla
          </Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={getSelectedKeys()}
          defaultOpenKeys={getOpenKeys()}
          items={menuItems}
          onClick={handleMenuClick}
        />
      </Sider>
      <Layout className="main-content">
        <Header className="header">
          <Title level={4} style={{ margin: 0 }}>
            CodeQL + LLM 安全分析平台
          </Title>
        </Header>
        <Content className="content">
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
};

export default MainLayout;
