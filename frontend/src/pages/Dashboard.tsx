import { Typography, Card, Row, Col, Statistic, Space } from 'antd';
import {
  BugOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  FolderOutlined,
} from '@ant-design/icons';
import './Dashboard.css';

const { Title, Paragraph } = Typography;

const Dashboard = () => {
  return (
    <div className="dashboard">
      <div className="page-header">
        <Title level={3} className="page-title">仪表盘</Title>
        <Paragraph type="secondary" className="page-subtitle">
          欢迎使用 Vulnhalla - 基于 CodeQL + LLM 的自动化安全分析平台
        </Paragraph>
      </div>

      <Row gutter={[24, 24]} className="stats-row">
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="项目总数"
              value={0}
              prefix={<FolderOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-danger">
            <Statistic
              title="已确认漏洞"
              value={0}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-warning">
            <Statistic
              title="待分析"
              value={0}
              prefix={<ExclamationCircleOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-success">
            <Statistic
              title="已排除"
              value={0}
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
      </Row>

      <Card className="quick-start-card">
        <Title level={4}>快速开始</Title>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Paragraph>
            1. 在「项目管理」中添加或选择要分析的项目
          </Paragraph>
          <Paragraph>
            2. 运行 CodeQL 查询并使用 LLM 进行分析
          </Paragraph>
          <Paragraph>
            3. 在「分析结果」中查看和筛选漏洞报告
          </Paragraph>
        </Space>
      </Card>
    </div>
  );
};

export default Dashboard;
