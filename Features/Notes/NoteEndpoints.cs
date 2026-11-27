using Notes_App.Features.Authentification;
using Notes_App.Features.Authorization;

namespace Notes_App.Features.Notes;

public static class NoteEndpoints
{
    public static RouteGroupBuilder MapNoteEndpoints(this RouteGroupBuilder builder)
    {
        var notes = builder.MapGroup("/notes");
        notes.MapGet("/", ListNotes);
        notes.MapGet("/{id}", GetNote);
        notes.MapPost("/", CreateNote);
        notes.MapPut("/{id}", UpdateNote);
        notes.MapDelete("/{id}", DeleteNote);
        return notes;
    }
    
    
    public static IResult ListNotes(HttpContext context)
    {
        var noteService = AppState.App.Services.GetRequiredService<NoteService>();
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        if (!authorizationService.TryGetUserId(context, out var userId))
            return authorizationService.Unauthorized(context);

        return Results.Ok(noteService.GetByOwnerId(userId));
    }

    public static IResult GetNote(int id, HttpContext context)
    {
        var noteService = AppState.App.Services.GetRequiredService<NoteService>();
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        if (!authorizationService.TryGetUserId(context, out var userId))
            return authorizationService.Unauthorized(context);

        var note = noteService.GetById(id);
        return note is null || note.OwnerId != userId ? Results.NotFound() : Results.Ok(note);
    }

    public static IResult CreateNote(NoteRequest? request, HttpContext context)
    {
        var noteService = AppState.App.Services.GetRequiredService<NoteService>();
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        if (!authorizationService.TryGetUserId(context, out var userId))
            return authorizationService.Unauthorized(context);
        if (request is null || string.IsNullOrWhiteSpace(request.Title))
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["A non-empty title is required."]
            });

        var note = noteService.Create(userId, request);
        return Results.Created($"/notes/{note.Id}", note);
    }

    public static IResult UpdateNote(int id, NoteRequest? request, HttpContext context)
    {
        var noteService = AppState.App.Services.GetRequiredService<NoteService>();
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        if (!authorizationService.TryGetUserId(context, out var userId))
            return authorizationService.Unauthorized(context);
        if (request is null || string.IsNullOrWhiteSpace(request.Title))
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["A non-empty title is required."]
            });

        var note = noteService.Update(id, userId, request);
        return note is null ? Results.NotFound() : Results.Ok(note);
    }

    public static IResult DeleteNote(int id, HttpContext context)
    {
        var noteService = AppState.App.Services.GetRequiredService<NoteService>();
        var authorizationService = AppState.App.Services.GetRequiredService<AuthorizationService>();
        
        if (!authorizationService.TryGetUserId(context, out var userId))
            return authorizationService.Unauthorized(context);

        return noteService.Delete(id, userId) ? Results.NoContent() : Results.NotFound();
    }   
}