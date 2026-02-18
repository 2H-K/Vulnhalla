import { Typography, Card, Empty } from 'antd';
import { FileSearchOutlined } from '@ant-design/icons';
import '../styles/Page.css';

const { Title, Paragraph } = Typography;

const Results = () => {
  return (
    <div className="results-page">
      <div className="page-header">
        <Title level={3}>分析结果</Title>
        <Paragraph type="secondary">
          查看 CodeQL + LLM 分析的漏洞报告
        </Paragraph>
      </div>
      <Card className="coming-soon-card">
        <Empty
          image={<FileSearchOutlined style={{ fontSize: 64, color: '#d9d9d9' }} />}
          description={
            <div>
              <Paragraph style={{ fontSize: 16, color: 'rgba(0, 0, 0, 0.65)' }}>
                分析结果功能开发中...
              </Paragraph>
            </div>
          }
        />
      </Card>
    </div>
  );
};

export default Results;
