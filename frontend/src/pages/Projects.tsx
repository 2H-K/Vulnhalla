import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Typography, 
  Card, 
  Row, 
  Col, 
  Button, 
  Table, 
  Space, 
  Tag, 
  Input, 
  Select, 
  Form, 
  Modal,
  message,
  Popconfirm,
  Tooltip,
  Badge,
  Divider,
  Collapse,
  Switch,
  InputNumber,
  Radio,
  Alert,
  Checkbox,
  Tabs,
} from 'antd';
import { 
  FolderOpenOutlined, 
  PlusOutlined, 
  EditOutlined, 
  DeleteOutlined, 
  PlayCircleOutlined,
  CodeOutlined,
  DatabaseOutlined,
  EyeOutlined,
  SyncOutlined,
  SettingOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
  RocketOutlined,
  ExperimentOutlined,
  ArrowRightOutlined,
  BookOutlined,
  AppstoreOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { Project, ProgrammingLanguage, ScanDepth, QueryType } from '../types';
import { LANGUAGE_LABELS, SCAN_DEPTH_CONFIGS, QUERY_TYPE_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph } = Typography;
const { Search } = Input;
const { Option } = Select;
const { Panel } = Collapse;

// 模拟项目数据
const mockProjects: Project[] = [
  {
    id: '1',
    name: 'fastbee 物联网平台',
    language: 'java',
    path: '/data/projects/fastbee',
    dbPath: '/output/databases/java/fastbee',
    status: 'ready',
    lastAnalyzed: '2026-02-15 14:30:22',
    issueCount: 8,
    createdAt: '2026-01-10',
    updatedAt: '2026-02-15',
  },
  {
    id: '2',
    name: 'redis C 源码',
    language: 'cpp',
    path: '/data/projects/redis',
    dbPath: '/output/databases/c/redis',
    status: 'analyzing',
    lastAnalyzed: '2026-02-18 09:15:45',
    issueCount: 12,
    createdAt: '2026-01-15',
    updatedAt: '2026-02-18',
  },
  {
    id: '3',
    name: 'ChanCMS',
    language: 'javascript',
    path: '/data/projects/ChanCMS',
    dbPath: '/output/databases/javascript/ChanCMS',
    status: 'ready',
    lastAnalyzed: '2026-02-10 16:20:33',
    issueCount: 5,
    createdAt: '2026-01-20',
    updatedAt: '2026-02-10',
  },
];

const languageOptions = [
  { value: 'java', label: 'Java' },
  { value: 'cpp', label: 'C/C++' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'csharp', label: 'C#' },
  { value: 'python', label: 'Python' },
  { value: 'go', label: 'Go' },
];

// 扫描深度选项
const scanDepthOptions = [
  { 
    value: 'shallow', 
    label: '浅度扫描', 
    description: '快速扫描，仅检测主要问题',
    icon: <RocketOutlined />,
    color: '#52c41a',
  },
  { 
    value: 'normal', 
    label: '常规扫描', 
    description: '平衡扫描速度和深度，推荐',
    icon: <ThunderboltOutlined />,
    color: '#1890ff',
  },
  { 
    value: 'deep', 
    label: '深度扫描', 
    description: '全面扫描，可能耗时较长',
    icon: <SettingOutlined />,
    color: '#722ed1',
  },
];

// 查询类型选项
const queryTypeOptions = [
  { 
    value: 'security-extended', 
    label: '安全扩展查询', 
    description: '包含更多安全检测规则，推荐使用',
    icon: <SafetyOutlined />,
  },
  { 
    value: 'security-and-quality', 
    label: '安全与质量查询', 
    description: '同时检测安全漏洞和代码质量问题',
    icon: <ExperimentOutlined />,
  },
  { 
    value: 'community', 
    label: '社区查询', 
    description: '使用社区维护的安全查询',
    icon: <AppstoreOutlined />,
  },
  { 
    value: 'custom', 
    label: '自定义查询', 
    description: '使用您自己编写或导入的查询',
    icon: <CodeOutlined />,
  },
];

const Projects = () => {
  const navigate = useNavigate();
  const [projects, setProjects] = useState(mockProjects);
  const [searchText, setSearchText] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [form] = Form.useForm();
  const [configTab, setConfigTab] = useState<string>('basic');

  // 过滤项目
  const filteredProjects = projects.filter(project => {
    const matchesSearch = project.name.toLowerCase().includes(searchText.toLowerCase()) ||
                         project.path.toLowerCase().includes(searchText.toLowerCase());
    const matchesLanguage = selectedLanguage === 'all' || project.language === selectedLanguage;
    return matchesSearch && matchesLanguage;
  });

  // 状态标签
  const getStatusTag = (status: string) => {
    const statusConfig: Record<string, { color: string; text: string }> = {
      ready: { color: 'green', text: '就绪' },
      analyzing: { color: 'blue', text: '分析中' },
      error: { color: 'red', text: '错误' },
      pending: { color: 'orange', text: '待处理' },
      completed: { color: 'purple', text: '已完成' },
    };
    const config = statusConfig[status] || { color: 'default', text: '未知' };
    return <Tag color={config.color}>{config.text}</Tag>;
  };

  // 处理添加项目 - 跳转到向导页面
  const handleAddProject = () => {
    navigate('/projects/new');
  };

  // 处理编辑项目
  const handleEditProject = (project: Project) => {
    setEditingProject(project);
    form.setFieldsValue({
      name: project.name,
      language: project.language,
      path: project.path,
      scanDepth: 'normal',
      queryType: 'security-extended',
      threads: 0,
      ramBudget: 4096,
      timeout: 300,
      enableLlmAnalysis: true,
      overwriteDatabase: true,
    });
    setIsModalOpen(true);
  };

  // 处理删除项目
  const handleDeleteProject = (id: string) => {
    setProjects(projects.filter(project => project.id !== id));
    message.success('项目已删除');
  };

  // 处理运行分析
  const handleRunAnalysis = (id: string) => {
    message.info('开始分析项目...');
    setProjects(projects.map(project => 
      project.id === id ? { ...project, status: 'analyzing' } : project
    ));
    
    setTimeout(() => {
      setProjects(projects.map(project => 
        project.id === id ? { 
          ...project, 
          status: 'ready', 
          lastAnalyzed: new Date().toISOString().replace('T', ' ').substring(0, 19),
          issueCount: Math.floor(Math.random() * 20) + 1
        } : project
      ));
      message.success('分析完成');
    }, 3000);
  };

  // 处理表单提交
  const handleSubmit = () => {
    form.validateFields().then(values => {
      if (editingProject) {
        setProjects(projects.map(project => 
          project.id === editingProject.id ? {
            ...project,
            name: values.name,
            language: values.language,
            path: values.path,
          } : project
        ));
        message.success('项目已更新');
      } else {
        const newProject: Project = {
          id: String(Date.now()),
          name: values.name,
          language: values.language,
          path: values.path,
          dbPath: `/output/databases/${values.language}/${values.name.replace(/\s+/g, '')}`,
          status: 'pending',
          lastAnalyzed: '从未分析',
          issueCount: 0,
          createdAt: new Date().toISOString().split('T')[0],
          updatedAt: new Date().toISOString().split('T')[0],
        };
        setProjects([...projects, newProject]);
        message.success('项目已添加');
      }
      setIsModalOpen(false);
    });
  };

  // 表格列定义
  const columns: ColumnsType<Project> = [
    {
      title: '项目名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: Project) => (
        <div>
          <div style={{ fontWeight: 500, fontSize: '16px' }}>
            <FolderOpenOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            {text}
          </div>
          <div style={{ fontSize: '12px', color: '#666', marginTop: 4 }}>
            <CodeOutlined /> {LANGUAGE_LABELS[record.language as ProgrammingLanguage]}
          </div>
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string, record: Project) => (
        <Space direction="vertical" size={4}>
          {getStatusTag(status)}
          {record.issueCount > 0 && (
            <Badge 
              count={`${record.issueCount} 个问题`} 
              style={{ backgroundColor: '#f5222d' }}
            />
          )}
        </Space>
      ),
    },
    {
      title: '路径',
      dataIndex: 'path',
      key: 'path',
      render: (text: string) => (
        <Tooltip title={text}>
          <div style={{ 
            maxWidth: 200, 
            overflow: 'hidden', 
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap'
          }}>
            <DatabaseOutlined style={{ marginRight: 4 }} />
            {text}
          </div>
        </Tooltip>
      ),
    },
    {
      title: '最后分析时间',
      dataIndex: 'lastAnalyzed',
      key: 'lastAnalyzed',
      render: (text: string) => (
        <Tag color={text === '从未分析' ? 'default' : 'blue'}>
          {text}
        </Tag>
      ),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Project) => (
        <Space size="small">
          <Tooltip title="运行分析">
            <Button 
              type="primary" 
              size="small" 
              icon={<PlayCircleOutlined />}
              onClick={() => handleRunAnalysis(record.id)}
              disabled={record.status === 'analyzing'}
            >
              {record.status === 'analyzing' ? '分析中...' : '分析'}
            </Button>
          </Tooltip>
          <Tooltip title="查看详情">
            <Button 
              size="small" 
              icon={<EyeOutlined />}
              onClick={() => navigate(`/projects/${record.id}`)}
            >
              详情
            </Button>
          </Tooltip>
          <Tooltip title="编辑项目">
            <Button 
              size="small" 
              icon={<EditOutlined />}
              onClick={() => handleEditProject(record)}
            >
              编辑
            </Button>
          </Tooltip>
          <Popconfirm
            title="确定要删除这个项目吗？"
            onConfirm={() => handleDeleteProject(record.id)}
            okText="确定"
            cancelText="取消"
          >
            <Tooltip title="删除项目">
              <Button 
                size="small" 
                danger 
                icon={<DeleteOutlined />}
              >
                删除
              </Button>
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div className="projects-page">
      <div className="page-header">
        <Title level={3}>项目管理</Title>
        <Paragraph type="secondary">
          管理待分析的代码项目和数据库，支持多种编程语言
        </Paragraph>
      </div>

      {/* 操作栏 */}
      <Card className="action-bar" style={{ marginBottom: 24 }}>
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} sm={12} md={8}>
            <Search
              placeholder="搜索项目名称或路径"
              allowClear
              onSearch={(value) => setSearchText(value)}
              onChange={(e) => setSearchText(e.target.value)}
              style={{ width: '100%' }}
            />
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Select
              placeholder="筛选语言"
              style={{ width: '100%' }}
              value={selectedLanguage}
              onChange={setSelectedLanguage}
            >
              <Option value="all">所有语言</Option>
              {languageOptions.map(lang => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Col>
          <Col xs={24} sm={24} md={10} style={{ textAlign: 'right' }}>
            <Space>
              <Button 
                icon={<SyncOutlined />}
                onClick={() => message.info('刷新功能开发中...')}
              >
                刷新
              </Button>
              <Button 
                type="primary" 
                icon={<PlusOutlined />}
                onClick={handleAddProject}
              >
                新建项目
              </Button>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 项目列表 */}
      <Card>
        <Table
          columns={columns}
          dataSource={filteredProjects}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          locale={{
            emptyText: (
              <div style={{ padding: '40px 0' }}>
                <FolderOpenOutlined style={{ fontSize: 48, color: '#d9d9d9', marginBottom: 16 }} />
                <div>暂无项目数据</div>
                <Button 
                  type="link" 
                  onClick={handleAddProject}
                  style={{ marginTop: 8 }}
                >
                  点击添加第一个项目
                </Button>
              </div>
            ),
          }}
        />
      </Card>

      {/* 编辑项目模态框 */}
      <Modal
        title={editingProject ? '编辑项目' : '添加新项目'}
        open={isModalOpen}
        onOk={handleSubmit}
        onCancel={() => {
          setIsModalOpen(false);
          setEditingProject(null);
        }}
        width={800}
        okText={editingProject ? '保存' : '创建项目'}
        cancelText="取消"
      >
        <Form
          form={form}
          layout="vertical"
          style={{ marginTop: 24 }}
        >
          {/* 基础信息 */}
          <Divider>基础信息</Divider>
          
          <Form.Item
            name="name"
            label="项目名称"
            rules={[{ required: true, message: '请输入项目名称' }]}
          >
            <Input placeholder="例如：fastbee 物联网平台" />
          </Form.Item>
          
          <Form.Item
            name="language"
            label="编程语言"
            rules={[{ required: true, message: '请选择编程语言' }]}
          >
            <Select placeholder="选择编程语言">
              {languageOptions.map(lang => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Form.Item>
          
          <Form.Item
            name="path"
            label="项目路径"
            rules={[{ required: true, message: '请输入项目路径' }]}
            extra="请输入项目源代码的绝对路径"
          >
            <Input placeholder="例如：D:/projects/myapp 或 /home/user/projects/myapp" />
          </Form.Item>

          {/* 扫描配置 */}
          <Divider>
            <SettingOutlined /> 扫描配置
          </Divider>

          <Tabs
            activeKey={configTab}
            onChange={setConfigTab}
            items={[
              {
                key: 'basic',
                label: '基础配置',
                children: (
                  <div>
                    {/* 查询类型选择 */}
                    <Form.Item
                      name="queryType"
                      label="查询类型"
                      tooltip="选择要运行的 CodeQL 查询类型"
                    >
                      <Radio.Group style={{ width: '100%' }}>
                        <Space direction="vertical" style={{ width: '100%' }} size="middle">
                          {queryTypeOptions.map(option => (
                            <Radio key={option.value} value={option.value} style={{ width: '100%' }}>
                              <Card size="small" style={{ marginLeft: 8, width: 'calc(100% - 32px)' }}>
                                <Space>
                                  <span style={{ fontSize: 18 }}>{option.icon}</span>
                                  <div>
                                    <div style={{ fontWeight: 500 }}>{option.label}</div>
                                    <div style={{ fontSize: 12, color: '#666' }}>{option.description}</div>
                                  </div>
                                </Space>
                              </Card>
                            </Radio>
                          ))}
                        </Space>
                      </Radio.Group>
                    </Form.Item>

                    {/* 扫描深度选择 */}
                    <Form.Item
                      name="scanDepth"
                      label="扫描深度"
                      tooltip="选择扫描的深度级别"
                    >
                      <Radio.Group style={{ width: '100%' }}>
                        <Row gutter={[16, 16]}>
                          {scanDepthOptions.map(option => (
                            <Col span={8} key={option.value}>
                              <Card 
                                size="small" 
                                hoverable
                                style={{ 
                                  border: `1px solid ${form.getFieldValue('scanDepth') === option.value ? option.color : '#d9d9d9'}`,
                                  textAlign: 'center'
                                }}
                              >
                                <Radio value={option.value}>
                                  <div>
                                    <div style={{ fontSize: 24, marginBottom: 8, color: option.color }}>
                                      {option.icon}
                                    </div>
                                    <div style={{ fontWeight: 500 }}>{option.label}</div>
                                    <div style={{ fontSize: 11, color: '#666' }}>{option.description}</div>
                                  </div>
                                </Radio>
                              </Card>
                            </Col>
                          ))}
                        </Row>
                      </Radio.Group>
                    </Form.Item>
                  </div>
                ),
              },
              {
                key: 'advanced',
                label: '高级配置',
                children: (
                  <div>
                    <Row gutter={[16, 16]}>
                      <Col span={12}>
                        <Form.Item
                          name="threads"
                          label="线程数"
                          tooltip="0 表示自动检测"
                        >
                          <InputNumber 
                            min={0} 
                            max={32} 
                            style={{ width: '100%' }}
                            placeholder="0 = 自动"
                          />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name="ramBudget"
                          label="内存限制 (MB)"
                          tooltip="CodeQL 使用的最大内存"
                        >
                          <InputNumber 
                            min={1024} 
                            max={32768} 
                            step={1024}
                            style={{ width: '100%' }}
                          />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name="timeout"
                          label="超时时间 (秒)"
                          tooltip="扫描超时时间"
                        >
                          <InputNumber 
                            min={60} 
                            max={3600} 
                            step={60}
                            style={{ width: '100%' }}
                          />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name="overwriteDatabase"
                          label="覆盖已有数据库"
                          valuePropName="checked"
                        >
                          <Switch checkedChildren="是" unCheckedChildren="否" />
                        </Form.Item>
                      </Col>
                    </Row>
                  </div>
                ),
              },
              {
                key: 'llm',
                label: 'LLM配置',
                children: (
                  <div>
                    <Form.Item
                      name="enableLlmAnalysis"
                      label="启用 LLM 分析"
                      valuePropName="checked"
                      tooltip="使用 AI 分析漏洞，减少误报"
                    >
                      <Switch 
                        checkedChildren="启用" 
                        unCheckedChildren="禁用" 
                        defaultChecked
                      />
                    </Form.Item>

                    <Alert
                      message="LLM 分析说明"
                      description="启用后，系统将使用大语言模型对检测到的漏洞进行智能分析，自动判断是否为真实漏洞还是误报，并提供修复建议。"
                      type="success"
                      showIcon
                    />
                  </div>
                ),
              },
            ]}
          />
        </Form>
      </Modal>
    </div>
  );
};

export default Projects;
