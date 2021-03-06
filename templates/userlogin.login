<?xml version="1.0" encoding="utf-16" standalone="yes"?>
<SessionManagement Version="1.2">
  <SessionManagementMode>Manual</SessionManagementMode>
  <AllowConcurrentLogins>True</AllowConcurrentLogins>
  <EnableJSXInLoginReplay>True</EnableJSXInLoginReplay>
  <UseAutomaticABL>True</UseAutomaticABL>
  <ValidTrafficLogin>False</ValidTrafficLogin>
  <ValidAblLogin>False</ValidAblLogin>
  <AutomaticLoginValidated>True</AutomaticLoginValidated>
  <RecordedSessionRequests>
    <request scheme="http" host="api.zentao.net" path="/updater-isLatest-9.6.3-.html" port="80" method="GET" RequestEncoding="28591" SessionRequestType="Login" ordinal="473" ValidationStatus="None" MultiStepTested="true" sequencePlaybackRequired="true">
      <raw encoding="none">GET /updater-isLatest-9.6.3-.html?lang=zh_cn HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Referer: http://127.0.0.1/zentao/user-login-L3plbnRhby8=.html
Connection: Keep-Alive
Host: api.zentao.net
Accept: application/x-ms-application, image/jpeg, application/xaml+xml, image/gif, image/pjpeg, application/x-ms-xbap, */*
Accept-Language: zh-CN

</raw>
      <parameter name="lang" captureIndex="0" value="zh_cn" type="QUERY" linkParamType="simplelink" separator="&amp;" operator="=" reportName="lang" />
      <response status="302" bodyEncoding="iso-8859-1">
        <body value="UEsDBBQAAAAIAJRZ0ExVlAO/ZQAAAJoAAAAEACQAZGF0YQoAIAAAAAAAAQAYAAksPOMfBdQBCSw84x8F1AEJLDzjHwXUAbPJKMnNsePlsslITUyxsynJLMlJtTM2MFJwyy/NS7HRhwjY6IOlgcqS8lMqFZLSk/Nz8otslcozMktSlUDiyal5JalFdjYZhsi6gTwbfagUyA6gAigvLz0zrwJZTh9kMpgBdREAUEsBAi0AFAAAAAgAlFnQTFWUA79lAAAAmgAAAAQAJAAAAAAAAAAAAAAAAAAAAGRhdGEKACAAAAAAAAEAGAAJLDzjHwXUAQksPOMfBdQBCSw84x8F1AFQSwUGAAAAAAEAAQBWAAAAqwAAAAAA" compressedBinaryValue="true" />
        <headers value="HTTP/1.1 302 Moved Temporarily&#xA;Content-Length: 154&#xD;&#xA;Location: http://api.zentao.net/islastest.html?lang=zh_cn&#xD;&#xA;Server: yunjiasu-nginx&#xD;&#xA;Set-Cookie: __cfduid=d4dfc26c39f9df3b6c254e38440de4abb1529118752; expires=Sun, 16-Jun-19 03:12:32 GMT; path=/; domain=.zentao.net; HttpOnly&#xD;&#xA;Connection: keep-alive&#xD;&#xA;CF-RAY: 42ba186b91c9485f-TNA&#xD;&#xA;Date: Sat, 16 Jun 2018 03:12:32 GMT&#xD;&#xA;Content-Type: text/html&#xD;&#xA;" />
      </response>
      <sessionCookies />
    </request>
    <request scheme="http" host="api.zentao.net" path="/islastest.html" port="80" method="GET" RequestEncoding="28591" SessionRequestType="Login" ordinal="474" ValidationStatus="None" MultiStepTested="true" sequencePlaybackRequired="true">
      <raw encoding="none">GET /islastest.html?lang=zh_cn HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Referer: http://127.0.0.1/zentao/user-login-L3plbnRhby8=.html
Connection: Keep-Alive
Host: api.zentao.net
Accept: application/x-ms-application, image/jpeg, application/xaml+xml, image/gif, image/pjpeg, application/x-ms-xbap, */*
Accept-Language: zh-CN

</raw>
      <parameter name="lang" captureIndex="0" value="zh_cn" type="QUERY" linkParamType="simplelink" separator="&amp;" operator="=" reportName="lang" />
      <response status="200" bodyEncoding="utf-8">
        <body value="UEsDBBQAAAAAAJRZ0EwAAAAAAAAAAAAAAAAEACQAZGF0YQoAIAAAAAAAAQAYABpTPOMfBdQBGlM84x8F1AEaUzzjHwXUAVBLAQItABQAAAAAAJRZ0EwAAAAAAAAAAAAAAAAEACQAAAAAAAAAAAAAAAAAAABkYXRhCgAgAAAAAAABABgAGlM84x8F1AEaUzzjHwXUARpTPOMfBdQBUEsFBgAAAAABAAEAVgAAAEYAAAAAAA==" compressedBinaryValue="true" />
        <headers value="HTTP/1.1 200 OK&#xA;Content-Length: 0&#xD;&#xA;Last-Modified: Thu, 12 Oct 2017 06:38:15 GMT&#xD;&#xA;Server: yunjiasu-nginx&#xD;&#xA;Set-Cookie: __cfduid=d4dfc26c39f9df3b6c254e38440de4abb1529118752; expires=Sun, 16-Jun-19 03:12:32 GMT; path=/; domain=.zentao.net; HttpOnly&#xD;&#xA;Connection: keep-alive&#xD;&#xA;Accept-Ranges: bytes&#xD;&#xA;CF-RAY: 42ba186c11de485f-TNA&#xD;&#xA;Date: Sat, 16 Jun 2018 03:12:32 GMT&#xD;&#xA;Content-Type: text/html&#xD;&#xA;" />
      </response>
      <sessionCookies />
    </request>
  </RecordedSessionRequests>
  <SessionVerifier>
    <Enable>False</Enable>
    <OutSession>False</OutSession>
    <Pattern Base64="False" />
    <PatternType>Text</PatternType>
  </SessionVerifier>
  <ActionBasedSequence RecordingBrowser="EmbeddedIE">
    <Enabled>False</Enabled>
    <UseAbl>True</UseAbl>
    <StartingUrl>http://127.0.0.1</StartingUrl>
    <Actions>
      <Action ActionType="Wait" BrowserIndex="0" ID="dc340a30-5115-461e-b416-b5712b4892aa">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <tagName name="A" />
            <attributes>
              <attribute key="NAME" value="wait(sec)" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <Value>0</Value>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Click" BrowserIndex="0" ID="30c4b8b6-03c0-46c6-bbf2-53923318d808">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <hybridXPath>.#zentao</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[0].DIV[0].DIV[0].DIV[1].A[0]</xPath>
            <tagName name="A" />
            <innerText>开源版</innerText>
            <attributes>
              <attribute key="id" value="zentao" />
              <attribute key="class" value="btn btn-success" />
              <attribute key="href" value="http://127.0.0.1/zentao/" />
              <attribute key="target" value="_self" />
            </attributes>
            <urlAttributes>
              <attribute key="href" value="/zentao/" />
            </urlAttributes>
          </ElementLocation>
        </ElementLocations>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Wait" BrowserIndex="0" ID="7251b5f0-0c27-4f46-9705-6cbaf528a25c">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <tagName name="A" />
            <attributes>
              <attribute key="NAME" value="wait(sec)" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <Value>0</Value>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Click" BrowserIndex="0" ID="1307cfa4-6d9c-4f43-a9b1-824ba8e41717">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <hybridXPath>.#account</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[1].FORM[0].TABLE[0].TBODY[0].TR[0].TD[0].INPUT[0]</xPath>
            <tagName name="INPUT" />
            <parentForm>&lt;FORM class="form-condensed" method="post" target="hiddenwin" /&gt;</parentForm>
            <attributes>
              <attribute key="id" value="account" />
              <attribute key="class" value="form-control" />
              <attribute key="type" value="text" />
              <attribute key="name" value="account" />
              <attribute key="jQuery191046649994598709165" value="" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Set" BrowserIndex="0" ID="ec841f48-1405-467a-88c7-353fbe629ac0">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <hybridXPath>.#account</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[1].FORM[0].TABLE[0].TBODY[0].TR[0].TD[0].INPUT[0]</xPath>
            <tagName name="INPUT" />
            <parentForm>&lt;FORM class="form-condensed" method="post" target="hiddenwin" /&gt;</parentForm>
            <attributes>
              <attribute key="id" value="account" />
              <attribute key="class" value="form-control" />
              <attribute key="value" value="a" />
              <attribute key="type" value="text" />
              <attribute key="name" value="account" />
              <attribute key="jQuery191046649994598709165" value="" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <Value Base64="true" Encrypted="true">P94KM6mGycHitFuyaO1xZQ==</Value>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Set" BrowserIndex="0" ID="b4488749-8184-4621-a6e3-64377a6749c4">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <hybridXPath>.#login-form.FORM[0].TABLE[0].TBODY[0].TR[1].TD[0].INPUT[0]</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[1].FORM[0].TABLE[0].TBODY[0].TR[1].TD[0].INPUT[0]</xPath>
            <tagName name="INPUT" />
            <parentForm>&lt;FORM class="form-condensed" method="post" target="hiddenwin" /&gt;</parentForm>
            <attributes>
              <attribute key="class" value="form-control" />
              <attribute key="value" value="cbf65658fce9ec2eeec85866e7e8ea58" />
              <attribute key="type" value="password" />
              <attribute key="name" value="password" />
              <attribute key="jQuery191046649994598709165" value="" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <Value Base64="true" Encrypted="true">DHyrDP6irLQkZKbrcrZ+3aMdV09/uF7unO+oxfowmnM=</Value>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Wait" BrowserIndex="0" ID="db6148d2-4bec-4d8a-8132-d9744690a4ec">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <tagName name="A" />
            <attributes>
              <attribute key="NAME" value="wait(sec)" />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <Value>0</Value>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="Click" BrowserIndex="0" ID="dc0b478e-1adf-4977-af9e-9303ec7da7a1">
        <ElementLocations>
          <ElementLocation isPreferred="False">
            <hybridXPath>.#submit</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[1].FORM[0].TABLE[0].TBODY[0].TR[3].TD[0].BUTTON[0]</xPath>
            <tagName name="BUTTON" />
            <innerText>登录</innerText>
            <parentForm>&lt;FORM class="form-condensed" method="post" target="hiddenwin" /&gt;</parentForm>
            <attributes>
              <attribute key="id" value="submit" />
              <attribute key="class" value="btn btn-primary" />
              <attribute key="type" value="submit" />
              <attribute key="data-loading" value="稍候..." />
            </attributes>
          </ElementLocation>
        </ElementLocations>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
      <Action ActionType="VerifyElementsExists" BrowserIndex="0" ID="4b0c7059-af16-437a-a933-aac0436448a0">
        <ElementLocations>
          <ElementLocation isPreferred="True">
            <hybridXPath>.#topnav.A[0]</hybridXPath>
            <xPath>.header[0].DIV[0].DIV[0].A[0]</xPath>
            <tagName name="A" />
            <innerText>退出</innerText>
            <attributes>
              <attribute key="href" value="http://127.0.0.1/zentao/user-logout.html" />
            </attributes>
            <urlAttributes>
              <attribute key="href" value="/zentao/user-logout.html" />
            </urlAttributes>
          </ElementLocation>
          <ElementLocation isPreferred="True">
            <hybridXPath>.#block1.DIV[0].DIV[0].DIV[0].UL[0].LI[3].A[0]</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[0].DIV[2].DIV[0].DIV[0].DIV[0].DIV[0].DIV[0].UL[0].LI[3].A[0]</xPath>
            <tagName name="A" />
            <innerText>永久关闭</innerText>
            <attributes>
              <attribute key="class" value="close-block" />
              <attribute key="onclick" value="return confirm('确定永久关闭该区块吗？闭后所有人都将无法使用该区块，可以在后台自定义中打开')" />
              <attribute key="href" value="http://127.0.0.1/zentao/block-close-1.html" />
              <attribute key="target" value="hiddenwin" />
            </attributes>
            <urlAttributes>
              <attribute key="href" value="/zentao/block-close-1.html" />
            </urlAttributes>
          </ElementLocation>
          <ElementLocation isPreferred="True">
            <hybridXPath>.#block2.DIV[0].DIV[0].DIV[0].UL[0].LI[3].A[0]</hybridXPath>
            <xPath>.DIV[0].DIV[0].DIV[0].DIV[2].DIV[1].DIV[0].DIV[0].DIV[0].DIV[0].UL[0].LI[3].A[0]</xPath>
            <tagName name="A" />
            <innerText>永久关闭</innerText>
            <attributes>
              <attribute key="class" value="close-block" />
              <attribute key="onclick" value="return confirm('确定永久关闭该区块吗？闭后所有人都将无法使用该区块，可以在后台自定义中打开')" />
              <attribute key="href" value="http://127.0.0.1/zentao/block-close-2.html" />
              <attribute key="target" value="hiddenwin" />
            </attributes>
            <urlAttributes>
              <attribute key="href" value="/zentao/block-close-2.html" />
            </urlAttributes>
          </ElementLocation>
        </ElementLocations>
        <ProxyOrdinalRequestBeforeAction>-1</ProxyOrdinalRequestBeforeAction>
      </Action>
    </Actions>
    <VerifyElementsActionThreshold>1</VerifyElementsActionThreshold>
    <LogoutRegex>log[_\-\s]?out|sign[_\-\s]?out|log[_\-\s]?off|sign[_\-\s]?off|exit|quit|bye-bye|clearuser|invalidate|记录|输出|签署|关闭|结束|退出|再见|清除用户|失效|sign out|sign off|log out|log off|disconnect|注销|注销|注销|注销|断开连接</LogoutRegex>
  </ActionBasedSequence>
  <VariablesDefinitions>
    <VariableDefinition IsRegularExpression="False" Name="">
      <VariableType>DefaultDefinitions</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="^BV_">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="^CFID">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="^CFTOKEN">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__VIEWSTATE">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__EVENTVALIDATION">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__REQUESTDIGEST">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__VIEWSTATEGENERATOR">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__EVENTARGUMENT">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>None</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__EVENTTARGET">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>None</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__VIEWSTATEID">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments>An id of the viewstate that is stored in the server's db. </Comments>
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__LASTFOCUS">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__SCROLLPOSITIONX">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__SCROLLPOSITIONY">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__PREVIOUSPAGE">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__CALLBACKID">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>None</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__CALLBACKPARAM">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>None</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="__VIEWSTATEFIELDCOUNT">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="__VIEWSTATE\d+">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path>/</Path>
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="wsdl">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="disco">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="javax.faces.viewstate">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="^BV_">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="JSESSIONID">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="IIS_COOKIELESS">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="ses|token">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments>Session cookie regular expression</Comments>
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="(?:server|user|u)_*id">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments>Server or user id</Comments>
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="JSESSIONID">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="PHPSESSID">
      <VariableType>Parameter</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="__utm.|vgnvisitor|_csuid|_csoot|WEBTRENDS_ID|WT_FPS|cookieenabledcheck|__qc[ab]|MintUnique|PD_STATEFUL|_sn|BCSI\\-">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments>Cookie that tracks visitor activity for a third-party application</Comments>
      <RequestIgnoreStatus>Full</RequestIgnoreStatus>
      <EntityIgnoreStatus>Full</EntityIgnoreStatus>
      <ExcludeFromTest>True</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="(ASPSESSIONID[a-zA-Z0-9]{8})">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>True</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="WC_AUTHENTICATION_(\d+)">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>True</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="True" Name="WC_USERACTIVITY_(\d+)">
      <VariableType>Cookie</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>None</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>True</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>True</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="GUID">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="NUMERIC">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="HEXDECIMAL">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
    <VariableDefinition IsRegularExpression="False" Name="DATE">
      <VariableType>Custom</VariableType>
      <Hosts />
      <Path />
      <Comments />
      <RequestIgnoreStatus>Value</RequestIgnoreStatus>
      <EntityIgnoreStatus>Value</EntityIgnoreStatus>
      <ExcludeFromTest>False</ExcludeFromTest>
      <SessionIDEnabled>False</SessionIDEnabled>
      <CaptureName />
      <CaptureIndex>-1</CaptureIndex>
      <VariableOrigin>TemplateDefined</VariableOrigin>
      <AlwaysSend>False</AlwaysSend>
      <IsGroup>False</IsGroup>
      <SessionID TrackingMethod="ExploreAndLogin">
        <Value />
      </SessionID>
    </VariableDefinition>
  </VariablesDefinitions>
  <CustomParameters>
    <CustomParameter LogicalName="JSESSIONID">
      <Pattern>;(?:JSESSIONID|jsessionid)=([^/]+)$</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
    <CustomParameter LogicalName="IIS_COOKIELESS">
      <Pattern>(\((?:[ASF]\([a-zA-Z0-9]+\)){1,3}\))</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
    <CustomParameter LogicalName="GUID">
      <Pattern>((\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1})</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
    <CustomParameter LogicalName="HEXDECIMAL">
      <Pattern>(([A-Fa-f0-9]{40})|([A-Fa-f0-9]{32}))</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
    <CustomParameter LogicalName="DATE">
      <Pattern>\b((19|20)\d\d[-/.](0[1-9]|1[012])[-/.](0[1-9]|[12][0-9]|3[01]))\b</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
    <CustomParameter LogicalName="NUMERIC">
      <Pattern>\b(\d{8,128})\b</Pattern>
      <NameGroupIndex>-1</NameGroupIndex>
      <ValueGroupIndex>1</ValueGroupIndex>
      <TargetSegment>Path</TargetSegment>
      <ResponsePattern />
      <Condition />
    </CustomParameter>
  </CustomParameters>
</SessionManagement>