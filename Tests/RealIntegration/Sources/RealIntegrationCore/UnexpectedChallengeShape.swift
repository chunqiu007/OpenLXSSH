import Foundation

/// Non-secret metadata for ONLY the first refused typed callback. The production
/// bridge already caps fields at65536 bytes and prompt count at32. Oversize test
/// inputs are marked invalid/truncated; no raw bytes are encoded or retained.
public struct UnexpectedChallengeShape: Encodable, Sendable {
    public struct Field: Encodable, Sendable {
        public let byteCount: Int
        public let sha256: String?
        public let truncated: Bool
        public init(_ data: Data) {
            byteCount = data.count
            truncated = data.count > UnexpectedChallengeShape.maximumFieldBytes
            sha256 = truncated ? nil : PrivateInput.sha256(data)
        }
    }
    public struct Prompt: Encodable, Sendable {
        public let field: Field
        public let echo: Bool
        public init(bytes: Data, echo: Bool) { field = Field(bytes); self.echo = echo }
    }
    public static let maximumPrompts = 32
    public static let maximumFieldBytes = 65536
    public let callbackOrdinal: Int
    public let nameField: Field
    public let instructionField: Field
    public let promptCount: Int
    public let prompts: [Prompt]
    public let truncated: Bool
    public let invalid: Bool
    public init(ordinal: Int, name: Data, instruction: Data, prompts: [Data], echo: [Bool]) {
        callbackOrdinal = ordinal
        nameField = Field(name); instructionField = Field(instruction); promptCount = prompts.count
        self.prompts = prompts.prefix(Self.maximumPrompts).enumerated().map { index, bytes in
            Prompt(bytes: bytes, echo: index < echo.count ? echo[index] : false)
        }
        truncated = prompts.count > Self.maximumPrompts || nameField.truncated || instructionField.truncated || self.prompts.contains { $0.field.truncated }
        invalid = ordinal < 1 || prompts.count != echo.count || truncated
    }
}
