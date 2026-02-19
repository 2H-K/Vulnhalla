import { useState, useEffect } from 'react';
import { 
  Typography, 
  Card, 
  Row, 
  Col, 
  Statistic, 
  Space, 
  Button, 
  Progress, 
  List, 
  Tag,
  Badge,
  Timeline,
  Alert
} from 'antd';
import {
  BugOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  FolderOutlined,
  RocketOutlined,
  LineChartOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  ClockCircleOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  PlayCircleOutlined,
  PlusOutlined,
  CodeOutlined
} from '@ant-design/icons';
import './Dashboard.css';

const { Title, Paragraph, Text } = Typography;

// 模拟统计数据
const mockStats = {
  totalProjects: 4,
  confirmedVulnerabilities: 28,
  pendingAnalysis: 1,
  excludedIssues: 15,
  languages: [
    { name: 'Java', count: 2, issues: 11 },
    { name: 'C', count: 1, issues: 12 },
    { name: 'JavaScript', count: 1, issues: 5 },
  ],
  recentActivities: [
    { time: '2026-02-18 09:15', action: '开始分析', project: 'redis C 源码', status: 'running' },
    { time: '2026-02-18 08:30', action: '分析完成', project: 'fastbee 物联网平台', status: 'success' },
    { time: '2026-02-17 16:45', action: '发现漏洞', project: 'ChanCMS', status: 'warning' },
    { time: '2026-02-17 10:20', action: '添加项目', project: 'webgoat', status: 'info' },
  ],
};

// 模拟最近项目
const recentProjects = [
  {
    id: '1',
    name: 'fastbee 物联网平台',
    language: 'Java',
    status: 'ready',
    lastAnalyzed: '2026-02-15 14:30:22',
    issueCount: 8,
    progress: 100,
  },
  {
    id: '2',
    name: 'redis C 源码',
    language: 'C',
    status: 'analyzing',
    lastAnalyzed: '2026-02-18 09:15:45',
    issueCount: 12,
    progress: 65,
  },
  {
    id: '3',
    name: 'ChanCMS',
    language: 'JavaScript',
    status: 'ready',
    lastAnalyzed: '2026-02-10 16:20:33',
    issueCount: 5,
    progress: 100,
  },
];

const Dashboard = () => {
  const [stats, setStats] = useState(mockStats);
  const [projects] = useState(recentProjects);

  // 模拟实时更新
  useEffect(() => {
    const interval = setInterval(() => {
      // 模拟进度更新
      setStats(prev => ({
        ...prev,
        pendingAnalysis: Math.random() > 0.5 ? 0 : 1,
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // 获取状态标签
  const getStatusTag = (status: string) => {
    const statusConfig: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
      ready: { color: 'success', text: '就绪', icon: <CheckCircleFilled /> },
      analyzing: { color: 'processing', text: '分析中', icon: <ClockCircleOutlined /> },
      error: { color: 'error', text: '错误', icon: <CloseCircleFilled /> },
    };
    const config = statusConfig[status] || { color: 'default', text: '未知', icon: null };
    return (
      <Tag color={config.color} icon={config.icon}>
        {config.text}
      </Tag>
    );
  };

  // 处理快速开始
  const handleQuickStart = (action: string) => {
    switch (action) {
      case 'addProject':
        window.location.href = '/projects';
        break;
      case 'runAnalysis':
        // 这里可以触发分析
        break;
      case 'viewResults':
        window.location.href = '/results';
        break;
    }
  };

  return (
    <div className="dashboard">
      <div className="page-header">
        <Title level={3} className="page-title">仪表盘</Title>
        <Paragraph type="secondary" className="page-subtitle">
          欢迎使用 Vulnhalla - 基于 CodeQL + LLM 的自动化安全分析平台
        </Paragraph>
      </div>

      {/* 统计数据行 */}
      <Row gutter={[24, 24]} className="stats-row">
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card">
            <Statistic
              title="项目总数"
              value={stats.totalProjects}
              prefix={<FolderOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
            <div style={{ marginTop: 8 }}>
              <Text type="secondary">
                {stats.languages.map(lang => lang.name).join(', ')}
              </Text>
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-danger">
            <Statistic
              title="已确认漏洞"
              value={stats.confirmedVulnerabilities}
              prefix={<BugOutlined />}
              valueStyle={{ color: '#f5222d' }}
            />
            <div style={{ marginTop: 8 }}>
              <Text type="secondary">
                高危: 8, 中危: 12, 低危: 8
              </Text>
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-warning">
            <Statistic
              title="待分析"
              value={stats.pendingAnalysis}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: '#fa8c16' }}
            />
            <div style={{ marginTop: 8 }}>
              <Progress 
                percent={65} 
                size="small" 
                status="active"
                strokeColor="#fa8c16"
              />
            </div>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card stat-success">
            <Statistic
              title="已排除"
              value={stats.excludedIssues}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
            <div style={{ marginTop: 8 }}>
              <Text type="secondary">
                误报率: 15%
              </Text>
            </div>
          </Card>
        </Col>
      </Row>

      {/* 主要功能区域 */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        {/* 左侧：快速开始和最近项目 */}
        <Col xs={24} lg={16}>
          {/* 快速开始卡片 */}
          <Card 
            title={
              <Space>
                <RocketOutlined />
                <span>快速开始</span>
              </Space>
            }
            className="quick-start-card"
            extra={
              <Button 
                type="link" 
                icon={<PlusOutlined />}
                onClick={() => handleQuickStart('addProject')}
              >
                添加项目
              </Button>
            }
          >
            <Row gutter={[16, 16]}>
              <Col xs={24} sm={8}>
                <Card 
                  hoverable
                  className="quick-action-card"
                  onClick={() => handleQuickStart('addProject')}
                >
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 32, color: '#1890ff', marginBottom: 8 }}>
                      <FolderOutlined />
                    </div>
                    <Title level={5} style={{ marginBottom: 8 }}>添加项目</Title>
                    <Paragraph type="secondary">
                      添加新的代码项目进行分析
                    </Paragraph>
                  </div>
                </Card>
              </Col>
              <Col xs={24} sm={8}>
                <Card 
                  hoverable
                  className="quick-action-card"
                  onClick={() => handleQuickStart('runAnalysis')}
                >
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 32, color: '#52c41a', marginBottom: 8 }}>
                      <PlayCircleOutlined />
                    </div>
                    <Title level={5} style={{ marginBottom: 8 }}>运行分析</Title>
                    <Paragraph type="secondary">
                      使用 CodeQL + LLM 分析项目
                    </Paragraph>
                  </div>
                </Card>
              </Col>
              <Col xs={24} sm={8}>
                <Card 
                  hoverable
                  className="quick-action-card"
                  onClick={() => handleQuickStart('viewResults')}
                >
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 32, color: '#722ed1', marginBottom: 8 }}>
                      <LineChartOutlined />
                    </div>
                    <Title level={5} style={{ marginBottom: 8 }}>查看结果</Title>
                    <Paragraph type="secondary">
                      查看分析结果和漏洞报告
                    </Paragraph>
                  </div>
                </Card>
              </Col>
            </Row>
          </Card>

          {/* 最近项目卡片 */}
          <Card 
            title={
              <Space>
                <ClockCircleOutlined />
                <span>最近项目</span>
              </Space>
            }
            style={{ marginTop: 24 }}
          >
            <List
              dataSource={projects}
              renderItem={(project) => (
                <List.Item
                  actions={[
                    <Button 
                      type="primary" 
                      size="small"
                      icon={<PlayCircleOutlined />}
                      disabled={project.status === 'analyzing'}
                    >
                      {project.status === 'analyzing' ? '分析中...' : '分析'}
                    </Button>,
                    <Button size="small">查看详情</Button>,
                  ]}
                >
                  <List.Item.Meta
                    avatar={
                      <div style={{
                        width: 40,
                        height: 40,
                        borderRadius: 8,
                        backgroundColor: '#1890ff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontSize: 18,
                      }}>
                        {project.language.charAt(0)}
                      </div>
                    }
                    title={
                      <Space>
                        <Text strong>{project.name}</Text>
                        {getStatusTag(project.status)}
                        {project.issueCount > 0 && (
                          <Badge 
                            count={`${project.issueCount} 个漏洞`} 
                            style={{ backgroundColor: '#f5222d' }}
                          />
                        )}
                      </Space>
                    }
                    description={
                      <Space direction="vertical" size={2}>
                        <Text type="secondary">
                          <CodeOutlined /> {project.language} · 
                          最后分析: {project.lastAnalyzed}
                        </Text>
                        {project.status === 'analyzing' && (
                          <Progress 
                            percent={project.progress} 
                            size="small" 
                            status="active"
                          />
                        )}
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          </Card>
        </Col>

        {/* 右侧：系统状态和最近活动 */}
        <Col xs={24} lg={8}>
          {/* 系统状态卡片 */}
          <Card 
            title={
              <Space>
                <SafetyCertificateOutlined />
                <span>系统状态</span>
              </Space>
            }
          >
            <Space direction="vertical" size="middle" style={{ width: '100%' }}>
              <Alert
                message="CodeQL 服务正常"
                type="success"
                showIcon
                icon={<CheckCircleFilled />}
              />
              <Alert
                message="LLM 服务正常"
                type="success"
                showIcon
                icon={<CheckCircleFilled />}
              />
              <Alert
                message="数据库连接正常"
                type="success"
                showIcon
                icon={<CheckCircleFilled />}
              />
              <Alert
                message="分析队列空闲"
                type="info"
                showIcon
                icon={<ClockCircleOutlined />}
              />
            </Space>
          </Card>

          {/* 最近活动卡片 */}
          <Card 
            title={
              <Space>
                <ThunderboltOutlined />
                <span>最近活动</span>
              </Space>
            }
            style={{ marginTop: 24 }}
          >
            <Timeline
              items={stats.recentActivities.map((activity) => ({
                color: activity.status === 'success' ? 'green' : 
                       activity.status === 'warning' ? 'orange' : 
                       activity.status === 'running' ? 'blue' : 'gray',
                children: (
                  <Space direction="vertical" size={2}>
                    <Text strong>{activity.action}</Text>
                    <Text type="secondary">{activity.project}</Text>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {activity.time}
                    </Text>
                  </Space>
                ),
              }))}
            />
          </Card>

          {/* 语言分布卡片 */}
          <Card 
            title="语言分布"
            style={{ marginTop: 24 }}
          >
            <Space direction="vertical" size="middle" style={{ width: '100%' }}>
              {stats.languages.map((lang) => (
                <div key={lang.name}>
                  <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Text>{lang.name}</Text>
                    <Space>
                      <Text type="secondary">{lang.count} 个项目</Text>
                      <Badge 
                        count={`${lang.issues} 个漏洞`} 
                        style={{ backgroundColor: '#1890ff' }}
                      />
                    </Space>
                  </Space>
                  <Progress 
                    percent={(lang.count / stats.totalProjects) * 100}
                    size="small"
                    showInfo={false}
                  />
                </div>
              ))}
            </Space>
          </Card>
        </Col>
      </Row>

      {/* 平台特性介绍 */}
      <Card 
        title="平台特性"
        style={{ marginTop: 24 }}
      >
        <Row gutter={[24, 24]}>
          <Col xs={24} sm={12} md={8}>
            <Card hoverable>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 32, color: '#1890ff', marginBottom: 16 }}>
                  🔍
                </div>
                <Title level={5}>CodeQL 静态分析</Title>
                <Paragraph type="secondary">
                  基于 GitHub CodeQL 的精准路径追踪和漏洞检测
                </Paragraph>
              </div>
            </Card>
          </Col>
          <Col xs={24} sm={12} md={8}>
            <Card hoverable>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 32, color: '#52c41a', marginBottom: 16 }}>
                  🧠
                </div>
                <Title level={5}>LLM 语义理解</Title>
                <Paragraph type="secondary">
                  利用大语言模型进行上下文理解和误报排除
                </Paragraph>
              </div>
            </Card>
          </Col>
          <Col xs={24} sm={12} md={8}>
            <Card hoverable>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 32, color: '#722ed1', marginBottom: 16 }}>
                  ⚡
                </div>
                <Title level={5}>自动化工作流</Title>
                <Paragraph type="secondary">
                  从代码扫描到漏洞报告的全自动化流程
                </Paragraph>
              </div>
            </Card>
          </Col>
        </Row>
      </Card>
    </div>
  );
};

export default Dashboard;
