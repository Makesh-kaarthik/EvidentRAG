import { useEffect, useRef, useState } from "react";
import suggestedQuestionBank from "./data/suggestedQuestions.json";
import "./App.css";

const initialMessages = [
  {
    id: 1,
    type: "assistant",
    content:
      "Welcome to Cyber EvidentRAG. Ask a cybersecurity question and I’ll retrieve and evaluate evidence before generating a response.",
    confidence: 0,
    coverage: 0,
    relevance: 0,
    sources: [],
  },
];

const SUGGESTION_GROUP_SIZE = 4;
const SUGGESTION_GROUP_COUNT = Math.ceil(suggestedQuestionBank.length / SUGGESTION_GROUP_SIZE);

function shuffleQuestions(questions) {
  const shuffled = [...questions];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = Math.floor(Math.random() * (index + 1));
    [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
  }
  return shuffled;
}
const knowledgeSources = [
  { label: "MITRE ATT&CK", keys: ["attack-pattern", "course-of-action", "x-mitre-tactic"] },
  { label: "CISA KEV", keys: ["cisa-kev"] },
  { label: "NVD / CVE details", keys: ["nvd-cve"] },
  { label: "Curated starter", keys: ["curated-starter"] },
];

const initialEvidenceData = {
  confidence: 0,
  coverage: 0,
  relevance: 0,
  verified: false,
  abstained: false,
  sources: [],
  pipeline: {
    query_processing: "Ready",
    hybrid_retrieval: "Ready",
    cross_encoder_reranking: "Ready",
    prompt_optimization: "Ready",
    evidence_verification: "Ready",
    response_generation: "Ready",
  },
};

function App() {
  const [query, setQuery] = useState("");
  const [models, setModels] = useState([]);
  const [selectedModel, setSelectedModel] = useState("");
  const [modelsUnavailable, setModelsUnavailable] = useState(false);
  const [suggestionGroup, setSuggestionGroup] = useState(0);
  const [suggestedQuestions] = useState(() => shuffleQuestions(suggestedQuestionBank));
  const [messages, setMessages] = useState(initialMessages);
  const [isProcessing, setIsProcessing] = useState(false);
  const [activeChat, setActiveChat] = useState("New Investigation");
  const [conversationId, setConversationId] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [turnCount, setTurnCount] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [conversationNotice, setConversationNotice] = useState("");
  const [evidenceData, setEvidenceData] = useState(initialEvidenceData);
  const [knowledgeStats, setKnowledgeStats] = useState(null);
  const messagesEndRef = useRef(null);
  const visibleSuggestions = suggestedQuestions.slice(
    suggestionGroup * SUGGESTION_GROUP_SIZE,
    (suggestionGroup + 1) * SUGGESTION_GROUP_SIZE,
  );

  useEffect(() => {
    let active = true;
    fetch("/api/models")
      .then((response) => {
        if (!response.ok) throw new Error("Model list unavailable");
        return response.json();
      })
      .then((data) => {
        if (!active) return;
        setModels(data.models || []);
        setSelectedModel(data.default_model || data.models?.[0]?.id || "");
      })
      .catch(() => {
        if (active) setModelsUnavailable(true);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    fetch("/api/knowledge/stats")
      .then((response) => {
        if (!response.ok) throw new Error("Knowledge statistics unavailable");
        return response.json();
      })
      .then((data) => { if (active) setKnowledgeStats(data); })
      .catch(() => { if (active) setKnowledgeStats({ unavailable: true }); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const loadConversations = async () => {
      try {
        const response = await fetch("/api/conversations");
        if (!response.ok) throw new Error("Conversation history unavailable");
        const data = await response.json();
        if (!active) return;
        const history = data.conversations || [];
        setConversations(history);
        const resumable = history.find((item) => item.turn_count < 6);
        if (resumable) {
          await openConversation(resumable.id, () => active);
        }
      } catch (error) {
        console.error("Conversation history failed:", error);
        if (active) setConversationNotice("Chat history is unavailable right now. Please check the database connection.");
      } finally {
        if (active) setHistoryLoading(false);
      }
    };
    loadConversations();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, isProcessing]);

  const createConversation = async (isActive = () => true) => {
    const response = await fetch("/api/conversations", { method: "POST" });
    if (!response.ok) throw new Error("Could not start a new investigation");
    const conversation = await response.json();
    if (isActive()) {
      setConversationId(conversation.id);
      setActiveChat(conversation.title);
      setMessages(initialMessages);
      setTurnCount(0);
      setEvidenceData(initialEvidenceData);
      setConversationNotice("");
    }
    setConversations((previous) => [
      conversation,
      ...previous.filter((item) => item.id !== conversation.id),
    ]);
    return conversation;
  };

  const openConversation = async (id, isActive = () => true) => {
    const response = await fetch(`/api/conversations/${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error("Could not load this investigation");
    const conversation = await response.json();
    if (!isActive()) return;
    setConversationId(conversation.id);
    setActiveChat(conversation.title || "New Investigation");
    setTurnCount(conversation.turn_count || 0);
    setConversationNotice("");
    const restored = (conversation.messages || []).map((message, index) => ({
      ...message,
      id: message.id || `${conversation.id}-${index}`,
      content: message.content || message.answer || "",
      confidence: Number(message.confidence || 0) / 100,
      coverage: Number(message.coverage || 0) / 100,
      relevance: Number(message.relevance || 0) / 100,
      sources: (message.sources || []).map((source) => ({
        title: source.title || "Unknown Source",
        type: source.source || source.type || "Unknown",
        score: Number(source.score) || 0,
        url: source.url || "",
        citationId: source.citation_id || source.citationId || "",
      })),
    }));
    setMessages(restored.length ? restored : initialMessages);
    const lastAssistant = [...restored].reverse().find((message) => message.type === "assistant");
    setEvidenceData(lastAssistant ? {
      confidence: lastAssistant.confidence || 0,
      coverage: lastAssistant.coverage || 0,
      relevance: lastAssistant.relevance || 0,
      verified: Boolean(lastAssistant.sufficient && !lastAssistant.abstained),
      abstained: Boolean(lastAssistant.abstained),
      sources: lastAssistant.sources || [],
      pipeline: lastAssistant.pipeline || initialEvidenceData.pipeline,
    } : initialEvidenceData);
  };

  /*
   * ============================================================
   * PROCESS QUERY
   * ============================================================
   *
   * This function is called ONLY when the user actually
   * submits the query.
   *
   * Suggestion buttons DO NOT call this function directly.
   */
  const processQuery = async (queryText) => {
    const trimmedQuery = queryText.trim();

    if (!trimmedQuery || isProcessing || historyLoading || turnCount >= 6) {
      return;
    }

    // Add user's question to the chat immediately
    const userMessage = {
      id: Date.now(),
      type: "user",
      content: trimmedQuery,
    };

    setQuery("");
    setIsProcessing(true);
    let requestConversationId = conversationId;

    try {
      if (!requestConversationId) {
        const created = await createConversation();
        requestConversationId = created.id;
      }
      setMessages((prev) => [...prev, userMessage]);
      setTurnCount((count) => Math.min(count + 1, 6));
      /*
       * Send query to FastAPI
       */
      const response = await fetch("/api/query", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query: trimmedQuery,
          model: selectedModel || undefined,
          conversation_id: requestConversationId,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));
        if (response.status === 409) {
          setMessages((prev) => prev.filter((message) => message.id !== userMessage.id));
          setConversationNotice(errorBody.detail || "This investigation has reached its six-question limit. Please start a new investigation to continue.");
          setTurnCount(6);
          setConversations((previous) => previous.map((item) => item.id === requestConversationId
            ? { ...item, turn_count: 6 }
            : item));
          return;
        }
        throw new Error(errorBody.detail || `API request failed: ${response.status}`);
      }

      const data = await response.json();
      if (turnCount + 1 >= 6) {
        setConversationNotice("You’ve reached the six-question limit for this investigation. Start a new investigation to continue.");
      }

      /*
       * FastAPI returns values such as:
       *
       * confidence: 87
       * coverage: 91
       * relevance: 94
       *
       * Frontend stores them as:
       *
       * 0.87
       * 0.91
       * 0.94
       */
      const confidence = Number(data.confidence) / 100;
      const coverage = Number(data.coverage) / 100;
      const relevance = Number(data.relevance) / 100;

      /*
       * Convert backend source structure
       * to frontend structure.
       */
      const sources = Array.isArray(data.sources)
        ? data.sources.map((source) => ({
            title: source.title || "Unknown Source",
            type: source.source || "Unknown",
            score: Number(source.score) || 0,
            url: source.url || "",
            citationId: source.citation_id || "",
          }))
        : [];

      /*
       * Pipeline status returned by FastAPI
       */
      const pipeline = data.pipeline || initialEvidenceData.pipeline;

      /*
       * Create assistant response
       */
      const assistantMessage = {
        id: Date.now() + 1,
        type: "assistant",
        content:
          data.answer || "No answer was returned by the EvidentRAG API.",
        confidence,
        coverage,
        relevance,
        sources,
        model: data.model || null,
        sufficient: Boolean(data.sufficient),
        abstained: Boolean(data.abstained),
      };

      /*
       * Add response to chat
       */
      setMessages((prev) => [...prev, assistantMessage]);
      const nextTitle = turnCount === 0 ? trimmedQuery.slice(0, 64) : activeChat;
      setActiveChat(nextTitle);
      setConversations((previous) => previous.map((item) => item.id === requestConversationId
        ? { ...item, title: nextTitle, turn_count: Math.min((item.turn_count || 0) + 1, 6), updated_at: new Date().toISOString() }
        : item).sort((left, right) => String(right.updated_at || "").localeCompare(String(left.updated_at || ""))));

      /*
       * Update Evidence Intelligence panel
       */
      setEvidenceData({
        confidence,
        coverage,
        relevance,
        verified: Boolean(data.sufficient && !data.abstained),
        abstained: Boolean(data.abstained),
        sources,
        pipeline,
      });
    } catch (error) {
      console.error("Query failed:", error);

      if (requestConversationId) {
        setMessages((prev) => prev.some((message) => message.id === userMessage.id)
          ? [...prev, {
              id: Date.now() + 1,
              type: "assistant",
              content: error.message || "Unable to process this question. Please try again.",
              confidence: 0,
              coverage: 0,
              relevance: 0,
              sources: [],
            }]
          : prev);
      } else {
        setQuery(trimmedQuery);
        setConversationNotice(error.message || "I couldn’t start an investigation. Please try again.");
      }
      if (turnCount + 1 >= 6) {
        setConversationNotice("You’ve reached the six-question limit for this investigation. Start a new investigation to continue.");
      }
      setConversations((previous) => previous.map((item) => item.id === requestConversationId
        ? { ...item, turn_count: Math.min((item.turn_count || 0) + 1, 6), updated_at: new Date().toISOString() }
        : item));

      /*
       * Reset evidence panel
       */
      setEvidenceData(initialEvidenceData);
    } finally {
      setIsProcessing(false);
    }
  };

  /*
   * ============================================================
   * NORMAL SUBMIT
   * ============================================================
   */
  const handleSubmit = () => {
    processQuery(query);
  };

  /*
   * ============================================================
   * KEYBOARD INPUT
   * ============================================================
   *
   * Enter       -> Submit
   * Shift+Enter -> New line
   */
  const handleKeyDown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      handleSubmit();
    }
  };

  /*
   * ============================================================
   * NEW INVESTIGATION
   * ============================================================
   */
  const handleNewInvestigation = () => {
    if (isProcessing) return;
    createConversation()
      .then(() => {
        setQuery("");
        setSuggestionGroup((current) => (current + 1) % SUGGESTION_GROUP_COUNT);
      })
      .catch(() => setConversationNotice("I couldn’t start a new investigation. Please try again."));
  };

  const handleOpenConversation = async (item) => {
    if (isProcessing || item.id === conversationId) return;
    try {
      await openConversation(item.id);
    } catch {
      setConversationNotice("I couldn’t load that investigation. Please try again.");
    }
  };

  const handleNextSuggestionGroup = () => {
    setSuggestionGroup((current) => (current + 1) % SUGGESTION_GROUP_COUNT);
  };

  /*
   * ============================================================
   * SUGGESTED QUESTIONS
   * ============================================================
   *
   * IMPORTANT CHANGE:
   *
   * Clicking a suggestion ONLY places the question
   * inside the chat input box.
   *
   * It does NOT send the request to FastAPI.
   */
  const handleSuggestion = (suggestion) => {
    if (isProcessing) {
      return;
    }

    setQuery(suggestion);
  };

  return (
    <div className="app">

      {/* ========================================================
          SIDEBAR
      ======================================================== */}

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">
            E
          </div>

          <div>

            <div className="brand-name">
              Cyber EvidentRAG
            </div>

            <div className="brand-subtitle">
              Evidence Intelligence
            </div>

          </div>

        </div>


        <button
          className="new-chat-button"
          onClick={handleNewInvestigation}
          disabled={isProcessing || historyLoading}
        >
          <span>＋</span>
          New Investigation
        </button>


        <div className="sidebar-section investigation-list">

          <div className="section-label">
            INVESTIGATIONS
          </div>


          {conversations.map((item) => (
            <button
              className={`chat-history-item ${item.id === conversationId ? "active" : ""}`}
              key={item.id}
              onClick={() => handleOpenConversation(item)}
              title={`${item.title} · ${item.turn_count || 0} of 6 questions`}
            >
              <span className="history-icon">◈</span>
              <span className="history-title">{item.title}</span>
              <span className="history-count">{item.turn_count || 0}/6</span>
            </button>
          ))}

        </div>


        <div className="sidebar-section">

          <div className="section-label">
            KNOWLEDGE SOURCES
          </div>
          <div className="knowledge-total">
            {knowledgeStats?.total?.toLocaleString() || "—"}
            <span> indexed records</span>
          </div>
          {knowledgeSources.map((source) => {
            const count = knowledgeStats?.by_source
              ? source.keys.reduce((sum, key) => sum + (knowledgeStats.by_source[key] || 0), 0)
              : 0;
            const available = Boolean(knowledgeStats?.by_source) && count > 0;
            return (
              <div className="source-status" key={source.label}>
                <span className={`status-dot${available ? " online" : ""}`}></span>
                <span>{source.label}</span>
                <span className="source-count">
                  {knowledgeStats?.unavailable ? "Unavailable" : knowledgeStats ? count.toLocaleString() : "Loading"}
                </span>
              </div>
            );
          })}

        </div>


        <div className="sidebar-footer">

          <div className="system-indicator">

            <span className="status-dot online"></span>

            Prototype ready

          </div>


          <div className="version">
            Cyber EvidentRAG v0.2
          </div>

        </div>

      </aside>


      {/* ========================================================
          MAIN CONTENT
      ======================================================== */}

      <main className="main-content">

        <header className="topbar">

          <div>

            <div className="page-title">
              {activeChat}
            </div>

            <div className="page-subtitle">
              Evidence-aware cybersecurity knowledge retrieval
            </div>

          </div>


          <div className="topbar-status">

            <span className="status-dot online"></span>

            Evidence-grounded prototype

          </div>

        </header>


        <section className="workspace">

          {/* ====================================================
              CHAT AREA
          ==================================================== */}

          <div className="chat-area">

            <div className="chat-header">

              <div>

                <h1>
                  Cybersecurity Intelligence Assistant
                </h1>

                <p>
                  Retrieve, verify and reason over trusted
                  cybersecurity knowledge.
                </p>

              </div>

            </div>


            {/* ==================================================
                MESSAGES
            ================================================== */}

            <div className="messages">

              {messages.map((message) => (

                <div
                  key={message.id}
                  className={`message-row ${message.type}`}
                >

                  {message.type === "assistant" && (

                    <div className="assistant-avatar">
                      E
                    </div>

                  )}


                  <div className="message-container">

                    <div className="message-label">
                      {message.type === "user" ? "YOU" : "EVIDENTRAG"}
                      {message.model && <span className="message-model"> · {message.model}</span>}
                    </div>


                    <div className="message-bubble">
                      <MessageContent content={message.content} sources={message.sources || []} />
                    </div>


                    {message.type === "assistant" &&
                      message.confidence > 0 && (

                        <div className="mini-evidence">

                          <span>
                              Evidence score{" "}
                            <strong>
                              {Math.round(
                                message.confidence * 100
                              )}
                              %
                            </strong>
                          </span>


                          <span>
                            Coverage{" "}
                            <strong>
                              {Math.round(
                                message.coverage * 100
                              )}
                              %
                            </strong>
                          </span>


                          <span>
                            Sources{" "}
                            <strong>
                              {message.sources.length}
                            </strong>
                          </span>

                        </div>

                    )}

                  </div>

                </div>

              ))}

              <div ref={messagesEndRef} aria-hidden="true" />


              {/* =================================================
                  PROCESSING INDICATOR
              ================================================= */}

              {isProcessing && (

                <div className="message-row assistant">

                  <div className="assistant-avatar">
                    E
                  </div>


                  <div className="message-container">

                    <div className="message-label">
                      EVIDENTRAG
                    </div>


                    <div className="processing-card">

                      <div className="processing-title">
                        Evidence Intelligence Pipeline
                      </div>


                      <div className="pipeline-steps">

                        <span className="completed">
                          Processing Question
                        </span>

                        <span className="completed">
                          Searching Knowledge Base
                        </span>

                        <span className="active-step">
                          Assessing Evidence
                        </span>

                      </div>


                      <div className="processing-loader">

                        <span></span>
                        <span></span>
                        <span></span>

                      </div>

                    </div>

                  </div>

                </div>

              )}

            </div>


            {/* ==================================================
                QUERY AREA
            ================================================== */}

            <div className="query-area">

              {conversationNotice && (
                <div className="conversation-notice" role="status">
                  <span>{conversationNotice}</span>
                  {turnCount >= 6 && (
                    <button type="button" onClick={handleNewInvestigation} disabled={isProcessing}>
                      Start new investigation
                    </button>
                  )}
                </div>
              )}

              <div className="conversation-limit" aria-live="polite">
                {historyLoading ? "Loading saved investigations…" : `${turnCount} of 6 questions used`}
              </div>

              {/* =================================================
                  SUGGESTED QUESTIONS
              ================================================= */}

              <div className="suggestion-section">
                <div className="suggestion-heading">
                  <span>Suggested questions · {suggestionGroup + 1} / {SUGGESTION_GROUP_COUNT}</span>
                  <button
                    type="button"
                    onClick={handleNextSuggestionGroup}
                    disabled={isProcessing}
                    aria-label="Show next suggested questions"
                    title="Show next group"
                  >
                    ↻
                  </button>
                </div>
                <div className="suggestions">
                  {visibleSuggestions.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      onClick={() => handleSuggestion(suggestion)}
                      disabled={isProcessing}
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>

              <div className="model-control">
                <label htmlFor="answer-model">Answer model</label>
                <select
                  id="answer-model"
                  value={selectedModel}
                  onChange={(event) => setSelectedModel(event.target.value)}
                  disabled={isProcessing || models.length === 0}
                  aria-describedby="model-description"
                >
                  {models.map((model) => (
                    <option key={model.id} value={model.id}>
                      {model.name}{model.description?.includes("Recommended") ? " · Recommended" : ""}
                    </option>
                  ))}
                </select>
                <span id="model-description">
                  {modelsUnavailable
                    ? "Model options unavailable; the backend default will be used."
                    : models.find((model) => model.id === selectedModel)?.description || "Choose the Gemini model for generated answers."}
                </span>
              </div>


              {/* =================================================
                  QUERY INPUT
              ================================================= */}

              <div className="query-box">

                <textarea
                  value={query}
                  onChange={(event) =>
                    setQuery(event.target.value)
                  }
                  onKeyDown={handleKeyDown}
                  placeholder="Ask a cybersecurity question..."
                  rows={1}
                  disabled={isProcessing || historyLoading || turnCount >= 6}
                />


                <button
                  className="send-button"
                  onClick={handleSubmit}
                  aria-label="Send question"
                  title="Send question"
                  disabled={
                    !query.trim() || isProcessing || historyLoading || turnCount >= 6
                  }
                >
                  ↑
                </button>

              </div>


              <div className="query-hint">
                Press Enter to submit • Shift + Enter for a new line
              </div>

            </div>

          </div>


          {/* ====================================================
              EVIDENCE PANEL
          ==================================================== */}

          <EvidencePanel
            evidenceData={evidenceData}
          />

        </section>

      </main>

    </div>
  );
}


/* ==============================================================
   EVIDENCE PANEL
   ============================================================== */

function MessageContent({ content, sources }) {
  const sourceByCitation = new Map(
    sources.map((source) => [source.citationId, source]),
  );
  return String(content || "")
    .split(/(\[E\d+\])/g)
    .map((part, index) => {
      const citation = part.match(/^\[(E\d+)\]$/)?.[1];
      const source = citation ? sourceByCitation.get(citation) : null;
      if (!source?.url) return <span key={index}>{part}</span>;
      return (
        <a key={index} href={source.url} target="_blank" rel="noreferrer">
          {part}
        </a>
      );
    });
}

function EvidencePanel({ evidenceData }) {

  const hasEvidence =
    evidenceData.sources.length > 0;
  const isVerified = Boolean(evidenceData.verified);

  return (

    <aside className="evidence-panel">

      <div className="evidence-header">

        <div>

          <div className="evidence-title">
            Evidence Intelligence
          </div>

          <div className="evidence-subtitle">
            Retrieval verification
          </div>

        </div>


        <div
          className={`verification-badge ${isVerified ? "verified" : hasEvidence ? "needs-review" : ""}`}
        >
          {isVerified ? "VERIFIED" : hasEvidence ? "CHECK NEEDED" : "WAITING"}
        </div>

      </div>


      <div className="evidence-content">

        {/* ======================================================
            METRICS
        ====================================================== */}

        <Metric
          label="Evidence Score"
          value={evidenceData.confidence}
        />


        <Metric
          label="Evidence Coverage"
          value={evidenceData.coverage}
        />


        <Metric
          label="Relevance"
          value={evidenceData.relevance}
        />


        <div className="evidence-divider"></div>


        {/* ======================================================
            SOURCES
        ====================================================== */}

        <div className="evidence-section-title">
          Retrieved Sources
        </div>


        {hasEvidence ? (

          evidenceData.sources.map(
            (source, index) => (

              <div
                className="evidence-source"
                key={index}
              >

                <div className="source-number">
                  {index + 1}
                </div>


                <div className="source-details">

                  <div className="source-title">
                    {source.url ? (
                      <a href={source.url} target="_blank" rel="noreferrer">
                        {source.title}
                      </a>
                    ) : source.title}
                  </div>


                  <div className="source-meta">

                    {source.citationId && <span>[{source.citationId}]</span>}

                    <span>
                      {source.type}
                    </span>


                    <span>
                      {Math.round(
                        Number(source.score) * 100
                      )}
                      % relevance
                    </span>

                  </div>

                </div>

              </div>

            )
          )

        ) : (

          <div className="empty-evidence">

            <div className="empty-icon">
              ◎
            </div>

            <p>
              Evidence retrieved for your query
              will appear here.
            </p>

          </div>

        )}


        <div className="evidence-divider"></div>


        {/* ======================================================
            PIPELINE STATUS
        ====================================================== */}

        <div className="evidence-section-title">
          Pipeline Status
        </div>


        <PipelineStatus
          label="Query Processing"
          status={
            evidenceData.pipeline.query_processing
          }
        />


        <PipelineStatus
          label="Hybrid Retrieval"
          status={
            evidenceData.pipeline.hybrid_retrieval
          }
        />


        <PipelineStatus
          label="Evidence Reranking"
          status={
            evidenceData.pipeline.cross_encoder_reranking
          }
        />


        <PipelineStatus
          label="Prompt Optimization"
          status={
            evidenceData.pipeline.prompt_optimization
          }
        />


        <PipelineStatus
          label="Evidence Verification"
          status={
            evidenceData.pipeline.evidence_verification
          }
        />


        <PipelineStatus
          label="Response Generation"
          status={
            evidenceData.pipeline.response_generation
          }
        />

      </div>

    </aside>
  );
}


/* ==============================================================
   METRIC COMPONENT
   ============================================================== */

function Metric({ label, value }) {

  const percentage = Math.round(
    Number(value) * 100
  );

  return (

    <div className="metric">

      <div className="metric-top">

        <span>
          {label}
        </span>


        <strong>
          {percentage}%
        </strong>

      </div>


      <div className="metric-bar">

        <div
          className="metric-fill"
          style={{
            width: `${percentage}%`,
          }}
        ></div>

      </div>

    </div>
  );
}


/* ==============================================================
   PIPELINE STATUS COMPONENT
   ============================================================== */

function PipelineStatus({
  label,
  status,
}) {

  const normalizedStatus =
    String(status || "").toLowerCase();

  const isComplete =
    normalizedStatus.startsWith("complete") ||
    normalizedStatus === "ready";

  return (

    <div className="pipeline-status">

      <span
        className={`status-dot ${
          isComplete ? "online" : ""
        }`}
      ></span>


      <span>
        {label}
      </span>


      <span className="pipeline-ready">
        {status}
      </span>

    </div>
  );
}


export default App;
