<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Generator;
use Illuminate\Http\Request;
use Laravel\Mcp\Exceptions\JsonRpcException;
use Laravel\Mcp\Server\Methods\CallTool;
use Laravel\Mcp\Server\ServerContext;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Transport\JsonRpcRequest;
use Laravel\Mcp\Transport\JsonRpcResponse;
use Throwable;

/** Laravel MCP tools/call enforcement for explicitly marked destructive tools. */
final class TwoPhaseCallTool extends CallTool
{
    public const int REFUSAL_CODE = -32001;

    public function __construct(
        private readonly CanonicalToolArguments $canonicalizer,
        private readonly TwoPhaseConfirmationStore $confirmations,
        private readonly TwoPhaseToolInvoker $invoker,
    ) {}

    /**
     * @return JsonRpcResponse|Generator<JsonRpcResponse>
     *
     * Pinned by `tests/McpTwoPhaseTest.php` — "previews without protected
     * execution then burns before executing at most once".
     */
    public function handle(JsonRpcRequest $request, ServerContext $context): Generator|JsonRpcResponse
    {
        if (is_null($request->get('name'))) {
            return parent::handle($request, $context);
        }

        /** @var Tool $tool */
        $tool = $context->tools()->first(
            fn (Tool $candidate): bool => $candidate->name() === $request->params['name'],
            fn () => throw new JsonRpcException(
                "Tool [{$request->params['name']}] not found.",
                -32602,
                $request->id,
            ),
        );

        if (TwoPhase::of($tool) === null) {
            return parent::handle($request, $context);
        }

        if (ToolEffect::of($tool)?->value !== Effect::Destructive
            || ! is_callable([$tool, TwoPhase::PREVIEW_METHOD])) {
            throw $this->refusal(TwoPhaseConfirmationRefused::UNAVAILABLE, $request);
        }

        try {
            $arguments = $request->get('arguments', []);

            if (! is_array($arguments) || ($arguments !== [] && array_is_list($arguments))) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
            }

            $confirmation = $arguments[TwoPhase::CONFIRM_ARGUMENT] ?? null;
            unset($arguments[TwoPhase::CONFIRM_ARGUMENT]);

            $protectedRequest = clone $request;
            $protectedRequest->params['arguments'] = $arguments;
            $httpRequest = app('request');

            if (! $httpRequest instanceof Request) {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::UNAVAILABLE);
            }

            $canonical = $this->canonicalizer->fromHttpRequest($httpRequest, $request);
            $subject = $this->confirmations->subject($httpRequest);

            if ($confirmation === null) {
                $preview = $this->invoker->preview($tool, $protectedRequest);

                if (($preview->content['result']['isError'] ?? false) === true) {
                    return $preview;
                }

                $minted = $this->confirmations->mint($tool->name(), $canonical, $subject);
                $preview->content['result']['_meta'][TwoPhase::META_KEY] = [
                    'phase' => 'preview',
                    'confirmation' => $minted['confirmation'],
                    'expires_at' => $minted['expires_at'],
                ];

                return $preview;
            }

            if (! is_string($confirmation) || $confirmation === '') {
                throw TwoPhaseConfirmationRefused::because(TwoPhaseConfirmationRefused::INVALID);
            }

            $this->confirmations->burn($confirmation, $tool->name(), $canonical, $subject);

            return $this->markExecuted($this->invoker->protected($tool, $protectedRequest));
        } catch (TwoPhaseConfirmationRefused $refused) {
            throw $this->refusal($refused->getMessage(), $request);
        } catch (JsonRpcException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw $this->refusal(TwoPhaseConfirmationRefused::INVALID, $request);
        }
    }

    /** @return JsonRpcResponse|Generator<JsonRpcResponse> */
    private function markExecuted(Generator|JsonRpcResponse $response): Generator|JsonRpcResponse
    {
        if ($response instanceof JsonRpcResponse) {
            $response->content['result']['_meta'][TwoPhase::META_KEY] = ['phase' => 'executed'];

            return $response;
        }

        return (function () use ($response): Generator {
            foreach ($response as $message) {
                if (isset($message->content['result']) && is_array($message->content['result'])) {
                    $message->content['result']['_meta'][TwoPhase::META_KEY] = ['phase' => 'executed'];
                }

                yield $message;
            }
        })();
    }

    private function refusal(string $reason, JsonRpcRequest $request): JsonRpcException
    {
        return new JsonRpcException($reason, self::REFUSAL_CODE, $request->id);
    }
}
