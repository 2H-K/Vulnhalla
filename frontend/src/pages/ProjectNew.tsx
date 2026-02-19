import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Typography,
  Card,
  Row,
  Col,
  Button,
  Form,
  Input,
  Select,
  Steps,
  Space,
  Divider,
  Alert,
  message,
  Switch,
  InputNumber,
  Checkbox,
  Radio,
  Tabs,
  List,
  Tag,
  Badge,
} from 'antd';
import {
  PlusOutlined,
  FolderOpenOutlined,
  CodeOutlined,
  SettingOutlined,
  SafetyOutlined,
  RocketOutlined,
  ThunderboltOutlined,
  ApiOutlined,
  AppstoreOutlined,
  BookOutlined,
  RobotOutlined,
  CheckCircleOutlined,
  ArrowRightOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons';
import type { ProgrammingLanguage, ScanDepth, QueryType, ScanConfig } from '../types';
import { LANGUAGE_LABELS, SCAN_DEPTH_CONFIGS, QUERY_TYPE_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph, Text } = Typography;
const { Option } = Select;
const { TextArea } = Input;

// 语言选项
const languageOptions = [
  { value: 'java', label: 'Java', icon: '☕' },
  { value: 'cpp', label: 'C/C++', icon: '⚙️' },
  { value: 'javascript', label: 'JavaScript/TypeScript', icon: '📜' },
  { value: 'csharp', label: 'C#', icon: '🔷' },
  { value: 'python', label: 'Python', icon: '🐍' },
  { value: 'go', label: 'Go', icon: '🐹' },
];

// 扫描深度选项
const scanDepthOptions = [
  {
    value: 'shallow',
    label: '浅度扫描',
    icon: <RocketOutlined />,
    description: '快速扫描，仅检测主要安全问题',
    color: '#52c41a',
  },
  {
    value: 'normal',
    label: '常规扫描',
    icon: <ThunderboltOutlined />,
    description: '平衡扫描速度和深度（推荐）',
    color: '#1890ff',
  },
  {
    value: 'deep',
    label: '深度扫描',
    icon: <SettingOutlined />,
    description: '全面扫描，包括实验性规则',
    color: '#722ed1',
  },
];

// 查询类型选项
const queryTypeOptions: { value: QueryType; label: string; description: string; icon: React.ReactNode }[] = [
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
    icon: <BookOutlined />,
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

const ProjectNew = () => {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);
  const [form] = Form.useForm();
  const [selectedLanguage, setSelectedLanguage] = useState<string>('');
  const [scanDepth, setScanDepth] = useState<ScanDepth>('normal');
  const [queryType, setQueryType] = useState<QueryType>('security-extended');

  // 表单初始值
  const initialValues: Partial<ScanConfig> = {
    language: 'java',
    sourceRoot: '',
    scanDepth: 'normal',
    queryType: 'security-extended',
    overwriteDatabase: true,
    threads: 0,
    ramBudget: 4096,
    timeout: 300,
    enableLlmAnalysis: true,
    excludeFalsePositives: true,
    includePaths: [],
    excludePaths: [],
    selectedPackages: [],
    selectedQueries: [],
  };

  // 下一步
  const handleNext = async () => {
    try {
      if (currentStep === 0) {
        // 验证基础信息
        await form.validateFields(['name', 'language', 'sourceRoot']);
      }
      setCurrentStep(currentStep + 1);
    } catch (error) {
      // 表单验证失败
    }
  };

  // 上一步
  const handlePrev = () => {
    setCurrentStep(currentStep - 1);
  };

  // 完成创建
  const handleFinish = (values: any) => {
    message.success('项目创建成功！');
    navigate('/projects');
  };

  // 步骤内容
  const stepItems = [
    {
      title: '基础信息',
      icon: <FolderOpenOutlined />,
    },
    {
      title: '扫描配置',
      icon: <SettingOutlined />,
    },
    {
      title: '查询设置',
      icon: <SafetyOutlined />,
    },
    {
      title: 'LLM 分析',
      icon: <RobotOutlined />,
    },
  ];

  return (
    <div className="project-new-page">
      <div className="page-header">
        <Title level={3}>创建新扫描项目</Title>
        <Paragraph type="secondary">
          配置您的代码扫描项目，设置扫描参数和分析选项
        </Paragraph>
      </div>

      {/* 步骤条 */}
      <Card style={{ marginBottom: 24 }}>
        <Steps
          current={currentStep}
          items={stepItems}
        />
      </Card>

      {/* 步骤内容 */}
      <Form
        form={form}
        layout="vertical"
        initialValues={initialValues}
        onFinish={handleFinish}
      >
        {/* 步骤 1: 基础信息 */}
        {currentStep === 0 && (
          <Card title="项目基础信息">
            <Row gutter={[24, 24]}>
              <Col xs={24} md={12}>
                <Form.Item
                  name="name"
                  label="项目名称"
                  rules={[
                    { required: true, message: '请输入项目名称' },
                    { min: 2, message: '项目名称至少2个字符' },
                  ]}
                >
                  <Input placeholder="例如：fastbee 物联网平台" size="large" />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item
                  name="language"
                  label="编程语言"
                  rules={[{ required: true, message: '请选择编程语言' }]}
                >
                  <Select
                    placeholder="选择编程语言"
                    size="large"
                    onChange={(value) => setSelectedLanguage(value)}
                  >
                    {languageOptions.map(lang => (
                      <Option key={lang.value} value={lang.value}>
                        <Space>
                          <span>{lang.icon}</span>
                          <span>{lang.label}</span>
                        </Space>
                      </Option>
                    ))}
                  </Select>
                </Form.Item>
              </Col>
              <Col xs={24}>
                <Form.Item
                  name="sourceRoot"
                  label="项目源代码路径"
                  rules={[
                    { required: true, message: '请输入项目源代码路径' },
                  ]}
                  extra="请输入项目源代码的根目录绝对路径"
                >
                  <Input
                    placeholder="例如：D:/projects/myapp 或 /home/user/projects/myapp"
                    size="large"
                    prefix={<FolderOpenOutlined />}
                  />
                </Form.Item>
              </Col>
            </Row>

            <Alert
              message="路径说明"
              description="请确保指定的路径包含完整的源代码文件。CodeQL 将扫描此目录下的所有源代码文件进行漏洞检测。"
              type="info"
              showIcon
              style={{ marginTop: 16 }}
            />
          </Card>
        )}

        {/* 步骤 2: 扫描配置 */}
        {currentStep === 1 && (
          <Card title="扫描配置">
            <Divider>扫描深度</Divider>
            <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
              {scanDepthOptions.map(option => (
                <Col xs={24} sm={8} key={option.value}>
                  <Card
                    hoverable
                    onClick={() => {
                      setScanDepth(option.value as ScanDepth);
                      form.setFieldsValue({ scanDepth: option.value });
                    }}
                    style={{
                      borderColor: scanDepth === option.value ? option.color : undefined,
                      borderWidth: scanDepth === option.value ? 2 : 1,
                    }}
                  >
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: 32, color: option.color, marginBottom: 8 }}>
                        {option.icon}
                      </div>
                      <div style={{ fontWeight: 500 }}>{option.label}</div>
                      <div style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
                        {option.description}
                      </div>
                    </div>
                  </Card>
                </Col>
              ))}
            </Row>

            <Divider>高级选项</Divider>
            <Row gutter={[16, 16]}>
              <Col xs={24} sm={12} md={6}>
                <Form.Item
                  name="threads"
                  label="线程数"
                  tooltip="0 表示自动检测系统可用线程数"
                >
                  <InputNumber
                    min={0}
                    max={32}
                    style={{ width: '100%' }}
                    placeholder="0 = 自动"
                  />
                </Form.Item>
              </Col>
              <Col xs={24} sm={12} md={6}>
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
              <Col xs={24} sm={12} md={6}>
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
              <Col xs={24} sm={12} md={6}>
                <Form.Item
                  name="overwriteDatabase"
                  label="覆盖已有数据库"
                  valuePropName="checked"
                >
                  <Switch checkedChildren="是" unCheckedChildren="否" />
                </Form.Item>
              </Col>
            </Row>
          </Card>
        )}

        {/* 步骤 3: 查询设置 */}
        {currentStep === 2 && (
          <Card title="查询设置">
            <Divider>查询类型</Divider>
            <Radio.Group
              value={queryType}
              onChange={(e) => {
                setQueryType(e.target.value);
                form.setFieldsValue({ queryType: e.target.value });
              }}
              style={{ width: '100%' }}
            >
              <Space direction="vertical" style={{ width: '100%' }} size="middle">
                {queryTypeOptions.map(option => (
                  <Radio key={option.value} value={option.value} style={{ width: '100%' }}>
                    <Card size="small" style={{ marginLeft: 8 }}>
                      <Space>
                        <span style={{ fontSize: 20 }}>{option.icon}</span>
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

            <Divider>路径过滤（可选）</Divider>
            <Row gutter={[16, 16]}>
              <Col xs={24}>
                <Form.Item
                  name="includePaths"
                  label="包含路径"
                  extra="仅扫描这些路径，留空表示扫描全部"
                >
                  <Select
                    mode="tags"
                    placeholder="输入路径后按回车"
                    style={{ width: '100%' }}
                  />
                </Form.Item>
              </Col>
              <Col xs={24}>
                <Form.Item
                  name="excludePaths"
                  label="排除路径"
                  extra="不扫描这些路径，如：node_modules, vendor, dist"
                >
                  <Select
                    mode="tags"
                    placeholder="输入路径后按回车"
                    style={{ width: '100%' }}
                  />
                </Form.Item>
              </Col>
            </Row>

            <Alert
              message="查询说明"
              description={
                <div>
                  <p>• <strong>安全扩展查询</strong>：覆盖主流安全漏洞（推荐）</p>
                  <p>• <strong>安全与质量查询</strong>：同时检测安全问题代码质量问题</p>
                  <p>• <strong>社区查询</strong>：使用社区维护的额外安全规则</p>
                  <p>• <strong>自定义查询</strong>：使用您自己编写或导入的 CodeQL 查询</p>
                </div>
              }
              type="info"
              showIcon
            />
          </Card>
        )}

        {/* 步骤 4: LLM 分析 */}
        {currentStep === 3 && (
          <Card title="LLM 智能分析配置">
            <Form.Item
              name="enableLlmAnalysis"
              valuePropName="checked"
            >
              <Space direction="vertical" style={{ width: '100%' }}>
                <Card>
                  <Space>
                    <Switch
                      checked={form.getFieldValue('enableLlmAnalysis')}
                      onChange={(checked) => form.setFieldsValue({ enableLlmAnalysis: checked })}
                      checkedChildren="启用"
                      unCheckedChildren="禁用"
                    />
                    <div>
                      <div style={{ fontWeight: 500 }}>启用 LLM 分析</div>
                      <div style={{ fontSize: 12, color: '#666' }}>
                        使用 AI 分析漏洞，减少误报
                      </div>
                    </div>
                  </Space>
                </Card>
              </Space>
            </Form.Item>

            {form.getFieldValue('enableLlmAnalysis') && (
              <>
                <Divider />

                <Form.Item
                  name="excludeFalsePositives"
                  valuePropName="checked"
                  tooltip="启用后，将自动尝试排除明显的误报"
                >
                  <Switch checkedChildren="是" unCheckedChildren="否" />
                  <span style={{ marginLeft: 8 }}>自动过滤误报</span>
                </Form.Item>

                <Alert
                  message="LLM 分析说明"
                  description={
                    <div>
                      <p>启用 LLM 分析后，系统将：</p>
                      <p>1. 使用大语言模型对检测到的漏洞进行智能分析</p>
                      <p>2. 自动判断是否为真实漏洞还是误报</p>
                      <p>3. 提供详细的修复建议和漏洞上下文</p>
                      <p>4. 根据分析结果对漏洞进行分类（真实漏洞/误报/需要更多信息）</p>
                    </div>
                  }
                  type="success"
                  showIcon
                  style={{ marginTop: 16 }}
                />
              </>
            )}
          </Card>
        )}

        {/* 底部按钮 */}
        <div style={{ marginTop: 24, textAlign: 'center' }}>
          <Space>
            {currentStep > 0 && (
              <Button
                size="large"
                icon={<ArrowLeftOutlined />}
                onClick={handlePrev}
              >
                上一步
              </Button>
            )}
            {currentStep < 3 ? (
              <Button
                type="primary"
                size="large"
                icon={<ArrowRightOutlined />}
                onClick={handleNext}
              >
                下一步
              </Button>
            ) : (
              <Button
                type="primary"
                size="large"
                icon={<CheckCircleOutlined />}
                htmlType="submit"
              >
                创建项目
              </Button>
            )}
          </Space>
        </div>
      </Form>
    </div>
  );
};

export default ProjectNew;
