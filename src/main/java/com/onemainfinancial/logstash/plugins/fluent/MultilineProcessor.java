package com.onemainfinancial.logstash.plugins.fluent;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.regex.Pattern;

import static com.onemainfinancial.logstash.plugins.fluent.Utils.getLong;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.getPattern;

public class MultilineProcessor {
    private static final Logger logger = LogManager.getLogger(FluentSession.class);
    public final boolean shouldContinue;
    private final String groupKey;
    private final String sourceField;
    private final Pattern pattern;
    private final Pattern discardPattern;
    private final String lineSeparator;
    private final boolean inverseMatch;
    private final long timeout;
    private final long maxMessages;
    private final Map<String, Pattern> match = new HashMap<>();
    private final FluentSecureForward parent;
    private final List<MultilineProcessor> multilineProcessors = new ArrayList<>();
    private final Map<String, MessageGroup> groups = new HashMap<>();
    private final Thread timeoutThread;

    public MultilineProcessor(Object object, FluentSecureForward fluentSecureForward) {
        try {
            Map<String, Object> config = (Map<String, Object>) object;
            this.parent = fluentSecureForward;
            this.sourceField = (String) config.getOrDefault("field", "message");
            this.groupKey = (String) config.getOrDefault("group_key", ">>default group<<");
            this.lineSeparator = (String) config.getOrDefault(("line_separator"), "\\n");
            this.pattern = getPattern((String) config.getOrDefault("pattern", ".*"));
            this.discardPattern = getPattern((String) config.get("discard_pattern"));
            this.inverseMatch = (Boolean) config.getOrDefault("inverse_match", false);
            this.timeout = getLong(config, "timeout", (long) 5000);
            this.maxMessages = getLong(config, "max_messages", (long) 0);
            this.shouldContinue = (Boolean) config.getOrDefault("continue", false);
            Object o = config.get("multiline");
            if (o != null) {
                if (o instanceof List) {
                    for (Object y : (List<Object>) o) {
                        multilineProcessors.add(new MultilineProcessor(y, fluentSecureForward));
                    }
                } else {
                    multilineProcessors.add(new MultilineProcessor(o, fluentSecureForward));
                }
            }
            Map<String, String> matchConfig = (Map<String, String>) config.get(("match"));
            if (matchConfig != null) {
                for (Map.Entry<String, String> e : matchConfig.entrySet()) {
                    match.put(e.getKey(), getPattern(e.getValue()));
                }
            }
            ExpansionPattern.getExpansions(this.groupKey);
            if (timeout > 0) {
                timeoutThread = new Thread(() -> {
                    while (!parent.isStopped()) {
                        try {
                            Thread.sleep(100);
                            long time = System.currentTimeMillis();
                            Iterator<Map.Entry<String, MessageGroup>> it = groups.entrySet().iterator();
                            while (it.hasNext()) {
                                Map.Entry<String, MessageGroup> e = it.next();
                                if ((time - e.getValue().updatedAt) > timeout) {
                                    it.remove();
                                    sendToNextProcessor(e.getValue().build());
                                }
                            }

                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                });
                timeoutThread.start();
            } else {
                timeoutThread = null;
            }

            logger.debug("Created multiline processor " + this);
        } catch (Exception e) {
            IllegalStateException e2 = new IllegalStateException(e.getMessage());
            e2.setStackTrace(e.getStackTrace());
            throw e2;
        }
    }

    private static String getStringFromEvent(String sourceField, Map<String, Object> map) {
        try {
            Object field = Utils.get(map, sourceField);
            return field == null ? null : field.toString();
        } catch (Exception e) {
            logger.error("Caught exception getting event value", e);
            return null;
        }
    }

    public void stop() {
        if (timeoutThread != null) {
            timeoutThread.interrupt();
        }
        for (MessageGroup g : groups.values()) {
            sendToNextProcessor(g.build());
        }
        for (MultilineProcessor p : multilineProcessors) {
            p.stop();
        }
    }

    public boolean shouldProcess(Map<String, Object> event) {
        try {
            for (Map.Entry<String, Pattern> e : match.entrySet()) {
                Object v = Utils.get(event, e.getKey());
                if (v == null) {
                    return false;
                }
                if (!e.getValue().matcher(v.toString()).matches()) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.error("Caught exception checking multiline match", e);
            return false;
        }
    }

    public void accept(Map<String, Object> map) {
        String fieldValue = getStringFromEvent(sourceField, map);
        boolean wasNull = false;
        boolean matches = false;
        if (fieldValue != null) {
            if (discardPattern != null && discardPattern.matcher(fieldValue).matches()) {
                return;
            }
            matches = pattern.matcher(fieldValue).matches();

            if (inverseMatch) {
                matches = !matches;
            }
        }
        String group = ExpansionPattern.expand(this.groupKey, map);
        boolean exists = groups.containsKey(group);
        if (exists && matches) {
            sendToNextProcessor(groups.remove(group).build());
            exists = false;
        }
        if (!exists) {
            groups.put(group, new MessageGroup(sourceField, map));
        }
        groups.get(group).add(fieldValue);

    }

    private void sendToNextProcessor(Map<String, Object> map) {
        boolean processed = false;
        for (MultilineProcessor processor : multilineProcessors) {
            if (processor.shouldProcess(map)) {
                processed = true;
                processor.accept(map);
                if (!processor.shouldContinue) {
                    return;
                }
            }
        }
        if (!processed) {
            parent.writeMessage(map);
        }
    }

    class MessageGroup {
        private final StringBuilder builder = new StringBuilder();
        private final Map<String, Object> event;
        private final String field;
        private int totalMessages = 0;
        private long updatedAt = 0;

        public MessageGroup(String field, Map<String, Object> event) {
            this.event = event;
            this.field = field;
        }

        public void add(String fieldValue) {
            updatedAt = System.currentTimeMillis();
            if (fieldValue == null || (maxMessages > 0 && totalMessages >= maxMessages)) {
                return;
            }
            totalMessages++;
            if (builder.length() > 0) {
                builder.append(lineSeparator);
            }
            builder.append(fieldValue);
        }

        public Map<String, Object> build() {
            Utils.set(event, field, builder.toString());
            return event;
        }
    }
}
