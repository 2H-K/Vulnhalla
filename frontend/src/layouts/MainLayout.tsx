import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Menu, Typography, theme } from 'antd';
import {
  DashboardOutlined,
  FolderOutlined,
  FileSearchOutlined,
  SettingOutlined,
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
    key: '/results',
    icon: <FileSearchOutlined />,
    label: '分析结果',
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
  const { token } = theme.useToken();

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key);
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
          selectedKeys={[location.pathname]}
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
