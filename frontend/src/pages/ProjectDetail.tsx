import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Typography,
  Card,
  Row,
  Col,
  Button,
  Space,
  Tag,
  Descriptions,
  Timeline,
  Progress,
  Statistic,
  Table,
  Tabs,
  message,
  Alert,
  Divider,
} from 'antd';
import {
  ArrowLeftOutlined,
  PlayCircleOutlined,
  SettingOutlined,
  DeleteOutlined,
  DownloadOutlined,
  SafetyOutlined,
  ClockCircleOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { Vulnerability, Severity } from '../types';
import { SEVERITY_COLORS, SEVERITY_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph, Text } = Typography;

// 模拟项目数据
const mockProject = {
  id: '1',
  name: 'fastbee 物联网平台',
  language: 'Java',
  path: '/data/projects/fastbee',
  dbPath: '/output/databases/java/fastbee',
  status: 'ready',
  lastAnalyzed: '2026-02-15 14:30:22',
  createdAt: '2026-01-10 10:00:00',
  issueCount: 8,
  scanConfig: {
    scanDepth: 'normal',
    queryType: 'security-extended',
    threads: 8,
    ramBudget: 4096,
    timeout: 300,
    enableLlmAnalysis: true,
  },
};

// 模拟漏洞数据
const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'v1',
    projectId: '1',
    projectName: 'fastbee 物联网平台',
    ruleId: 'java/sql-injection',
    ruleName: 'SQL 注入',
    severity: 'high',
    confidence: 'high',
    status: 'new',
    filePath: 'src/main/java/com/fastbee/mapper/UserMapper.java',
    startLine: 42,
    endLine: 45,
    startColumn: 5,
    endColumn: 30,
    codeSnippet: 'String sql = "SELECT * FROM users WHERE id = " + userId;',
    message: '可能存在 SQL 注入漏洞',
    description: '使用字符串拼接构建 SQL 查询可能导致 SQL 注入攻击',
    dataFlow: [],
    detectedAt: '2026-02-15 14:30:22',
    updatedAt: '2026-02-15 14:30:22',
  },
  {
    id: 'v2',
    projectId: '1',
    projectName: 'fastbee 物联网平台',
    ruleId: 'java/path-traversal',
    ruleName: '路径遍历',
    severity: 'medium',
    confidence: 'medium',
    status: 'confirmed',
    filePath: 'src/main/java/com/fastbee/utils/FileUtils.java',
    startLine: 78,
    endLine: 80,
    startColumn: 10,
    endColumn: 45,
    codeSnippet: 'File file = new File(baseDir + "/" + filename);',
    message: '可能存在路径遍历漏洞',
    description: '用户输入直接用于文件路径可能导致目录遍历攻击',
    dataFlow: [],
    detectedAt: '2026-02-15 14:30:25',
    updatedAt: '2026-02-16 10:20:00',
  },
];

const ProjectDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [analyzing, setAnalyzing] = useState(false);

  // 处理运行分析
  const handleRunAnalysis = () => {
    setAnalyzing(true);
    message.info('开始分析项目...');
    
    // 模拟分析过程
    setTimeout(() => {
      setAnalyzing(false);
      message.success('分析完成！');
    }, 3000);
  };

  // 漏洞表格列
  const columns: ColumnsType<Vulnerability> = [
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: Severity) => (
        <Tag color={SEVERITY_COLORS[severity]}>
          {SEVERITY_LABELS[severity]}
        </Tag>
      ),
    },
    {
      title: '漏洞类型',
      dataIndex: 'ruleName',
      key: 'ruleName',
    },
    {
      title: '位置',
      dataIndex: 'filePath',
      key: 'filePath',
      render: (text, record) => (
        <Text code>
          {record.filePath}:{record.startLine}
        </Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status) => (
        <Tag color={status === 'new' ? 'blue' : status === 'confirmed' ? 'red' : 'green'}>
          {status === 'new' ? '新发现' : status === 'confirmed' ? '已确认' : '误报'}
        </Tag>
      ),
    },
  ];

  // Tab 内容
  const tabItems = [
    {
      key: 'overview',
      label: '概览',
      children: (
        <Row gutter={[24, 24]}>
          <Col xs={24} md={12}>
            <Card title="项目信息">
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="项目名称">{mockProject.name}</Descriptions.Item>
                <Descriptions.Item label="编程语言">{mockProject.language}</Descriptions.Item>
                <Descriptions.Item label="源代码路径">{mockProject.path}</Descriptions.Item>
                <Descriptions.Item label="数据库路径">{mockProject.dbPath}</Descriptions.Item>
                <Descriptions.Item label="创建时间">{mockProject.createdAt}</Descriptions.Item>
                <Descriptions.Item label="最后分析时间">{mockProject.lastAnalyzed}</Descriptions.Item>
              </Descriptions>
            </Card>
          </Col>
          <Col xs={24} md={12}>
            <Card title="扫描统计">
              <Row gutter={[16, 16]}>
                <Col span={12}>
                  <Statistic
                    title="总漏洞数"
                    value={mockProject.issueCount}
                    prefix={<SafetyOutlined />}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="高危漏洞"
                    value={2}
                    valueStyle={{ color: SEVERITY_COLORS.high }}
                  />
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>
      ),
    },
    {
      key: 'vulnerabilities',
      label: '漏洞列表',
      children: (
        <Card>
          <Table
            columns={columns}
            dataSource={mockVulnerabilities}
            rowKey="id"
            pagination={{ pageSize: 10 }}
          />
        </Card>
      ),
    },
    {
      key: 'config',
      label: '扫描配置',
      children: (
        <Card>
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="扫描深度">{mockProject.scanConfig.scanDepth}</Descriptions.Item>
            <Descriptions.Item label="查询类型">{mockProject.scanConfig.queryType}</Descriptions.Item>
            <Descriptions.Item label="线程数">{mockProject.scanConfig.threads}</Descriptions.Item>
            <Descriptions.Item label="内存限制">{mockProject.scanConfig.ramBudget} MB</Descriptions.Item>
            <Descriptions.Item label="超时时间">{mockProject.scanConfig.timeout} 秒</Descriptions.Item>
            <Descriptions.Item label="LLM 分析">
              {mockProject.scanConfig.enableLlmAnalysis ? '已启用' : '已禁用'}
            </Descriptions.Item>
          </Descriptions>
        </Card>
      ),
    },
  ];

  return (
    <div className="project-detail-page">
      {/* 顶部导航 */}
      <div style={{ marginBottom: 24 }}>
        <Button
          type="link"
          icon={<ArrowLeftOutlined />}
          onClick={() => navigate('/projects')}
        >
          返回项目列表
        </Button>
      </div>

      {/* 项目标题和操作 */}
      <Card style={{ marginBottom: 24 }}>
        <Row justify="space-between" align="middle">
          <Col>
            <Space>
              <Title level={3} style={{ margin: 0 }}>{mockProject.name}</Title>
              <Tag color="green">{mockProject.status === 'ready' ? '就绪' : '分析中'}</Tag>
            </Space>
            <Paragraph type="secondary" style={{ marginTop: 8 }}>
              <ClockCircleOutlined /> 最后分析：{mockProject.lastAnalyzed}
            </Paragraph>
          </Col>
          <Col>
            <Space>
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={handleRunAnalysis}
                loading={analyzing}
              >
                {analyzing ? '分析中...' : '运行分析'}
              </Button>
              <Button icon={<SettingOutlined />}>配置</Button>
              <Button icon={<DownloadOutlined />}>导出报告</Button>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 分析进度（如果有） */}
      {analyzing && (
        <Alert
          message="正在分析..."
          description={
            <div>
              <Progress percent={75} status="active" />
              <Text type="secondary">正在执行 CodeQL 查询并分析结果...</Text>
            </div>
          }
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      {/* Tab 内容 */}
      <Tabs
        items={tabItems}
      />
    </div>
  );
};

export default ProjectDetail;
